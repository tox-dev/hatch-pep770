//! A zip archive that is not a wheel, such as a zipapp, described as the project's distribution plus every wheel it
//! bundles, as a file or unpacked.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rayon::prelude::*;

use crate::email::Metadata;
use crate::error::{Error, Result};
use crate::hashes::Hasher;
use crate::json::{Json, Obj};
use crate::model::{
    BundledInfo, Contributions, Facts, Identity, Settings, bundled_wheel_component, component_from_metadata, contributed_properties, file_component,
    formulation, project_identity, script_tool, timestamp, tool_components, vendored_dependencies, with_header,
};
use crate::names::{SBOM_FILE, purl};
use crate::record::{RecordRow, to_hex};
use crate::wheel::{BundledWheel, Opened, read_bundled_wheel};

/// one member, by the distribution that owns it
enum Item {
    File(RecordRow),
    Wheel(std::result::Result<Arc<BundledWheel>, String>),
}

pub struct Scan {
    pub name: String,
    pub identity: Identity,
    pub settings: Settings,
    version: Option<String>,
    root_ref: String,
    loose: Vec<RecordRow>,
    /// every distribution directory, sorted, with its metadata and members
    distributions: Vec<(String, Arc<Metadata>, Vec<(String, Item)>)>,
    /// the paths a content provider is asked about, in the order the Python reader asked
    pub queries: Vec<String>,
}

fn file_row(name: &str, content: &[u8]) -> RecordRow {
    let mut hasher = Hasher::new("sha256").expect("sha256");
    hasher.update(content);
    RecordRow { path: name.to_owned(), algorithm: "SHA-256".to_owned(), digest: to_hex(&hasher.finish()), size: content.len().to_string() }
}

/// where `extractall` writes a member: no drive, no empty, `.` or `..` parts
fn extract_target(unpacked: &Path, name: &str) -> PathBuf {
    let mut target = unpacked.to_path_buf();
    for part in name.split(['/', std::path::MAIN_SEPARATOR]) {
        if !matches!(part, "" | "." | "..") {
            target.push(part);
        }
    }
    target
}

impl Scan {
    /// `_read_archive`: read and unpack the archive, so a content provider can read its files as it reads the
    /// project's
    pub fn open(archive_path: &Path, unpacked: &Path, settings: Settings) -> Result<Self> {
        let archive_name = archive_path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
        let opened = Opened::path(archive_path, &archive_name)?;
        let own = format!("{archive_name}.cdx.json");
        let mut members: Vec<&str> = opened.archive.names().filter(|name| !name.ends_with('/') && *name != own).collect();
        members.sort_unstable();
        // every member read once, in parallel: written out for the provider, hashed, and kept for metadata and wheels
        let contents: Vec<Result<(String, Vec<u8>)>> = opened
            .archive
            .entries
            .par_iter()
            .map(|entry| {
                let target = extract_target(unpacked, &entry.name);
                if entry.is_dir() {
                    std::fs::create_dir_all(&target)?;
                    return Ok((entry.name.clone(), Vec::new()));
                }
                let content = opened.archive.read(entry, None).map_err(|error| opened.zip(error))?.expect("no limit").into_owned();
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&target, &content)?;
                Ok((entry.name.clone(), content))
            })
            .collect();
        let mut by_name: HashMap<String, Vec<u8>> = HashMap::with_capacity(contents.len());
        for content in contents {
            let (name, bytes) = content?;
            by_name.insert(name, bytes);
        }
        let mut metadata: BTreeMap<String, Arc<Metadata>> = BTreeMap::new();
        let mut order: Vec<String> = Vec::new();
        for name in members.iter().filter(|name| name.ends_with(".dist-info/METADATA")) {
            let key = if name.matches('/').count() > 1 { format!("{}/", name.rsplitn(3, '/').last().unwrap_or("")) } else { String::new() };
            let raw = String::from_utf8(by_name[*name].clone()).map_err(|error| Error::Value(format!("'utf-8' codec can't decode {name}: {error}")))?;
            // read_text: universal newlines
            let text = if raw.contains('\r') { raw.replace("\r\n", "\n").replace('\r', "\n") } else { raw };
            if !metadata.contains_key(&key) {
                order.push(key.clone());
            }
            metadata.insert(key, Arc::new(Metadata::parse(&text)));
        }
        let top = members.iter().filter(|name| name.matches('/').count() == 1 && name.ends_with(".dist-info/METADATA")).count();
        if top != 1 {
            return Err(Error::Wheel(format!("{archive_name} holds {top} top-level .dist-info/METADATA, not the one naming the project")));
        }
        let mut owned: BTreeMap<String, Vec<String>> = metadata.keys().map(|prefix| (prefix.clone(), Vec::new())).collect();
        let mut loose_names = Vec::new();
        for name in &members {
            let owner = order
                .iter()
                .filter(|prefix| !prefix.is_empty() && name.starts_with(prefix.as_str()))
                .fold(None::<&String>, |best, prefix| match best {
                    Some(best) if best.len() >= prefix.len() => Some(best),
                    _ => Some(prefix),
                });
            if let Some(owner) = owner {
                owned.get_mut(owner).expect("a known prefix").push((*name).to_owned());
            } else if name.contains('/') {
                owned.get_mut("").expect("checked above").push((*name).to_owned());
            } else {
                loose_names.push((*name).to_owned());
            }
        }
        let project = metadata[""].clone();
        let identity = project_identity(&project, &settings);
        let version = project.get("Version").map(str::to_owned);
        let root_ref = purl("generic", &archive_name, version.as_deref());
        let loose: Vec<RecordRow> = loose_names.par_iter().map(|name| file_row(name, &by_name[name])).collect();
        let mut queries = Vec::new();
        let mut distributions = Vec::with_capacity(metadata.len());
        for (prefix, distribution) in &metadata {
            if !prefix.is_empty() {
                queries.push(prefix.trim_end_matches('/').to_owned());
            }
            let names = &owned[prefix];
            queries.extend(names.iter().filter(|name| name.ends_with(".whl")).cloned());
            let items: Vec<(String, Item)> = names
                .par_iter()
                .map(|name| {
                    let content = &by_name[name];
                    let item = if name.ends_with(".whl") {
                        Item::Wheel(read_bundled_wheel(content.clone(), name).map(Arc::new).map_err(|error| error.to_string()))
                    } else {
                        Item::File(file_row(name, content))
                    };
                    (name.clone(), item)
                })
                .collect();
            distributions.push((prefix.clone(), distribution.clone(), items));
        }
        Ok(Self { name: archive_name, identity, settings, version, root_ref, loose, distributions, queries })
    }

    /// `describe_archive` once the content provider answered every query and made its contributions
    pub fn finish(
        &self,
        infos: &[BundledInfo],
        contributions: Contributions,
        facts: &Facts,
        scripts: &[(String, Vec<u8>)],
    ) -> Result<Json> {
        let prefix = &self.identity.property_prefix;
        let mut answers = infos.iter();
        let mut next_info = || answers.next().cloned().unwrap_or_default();
        let mut components = Vec::with_capacity(self.distributions.len() + contributions.components.len());
        for (directory, metadata, items) in &self.distributions {
            let mut component = component_from_metadata(metadata);
            if !directory.is_empty() {
                let directory = directory.trim_end_matches('/');
                let info = next_info();
                let reference = format!("bundled:{directory}");
                component.set("bom-ref", Json::Str(reference));
                if let Some(supplier) = info.supplier {
                    component.set("supplier", supplier);
                }
                let own = match component.get_mut("properties") {
                    Some(Json::Arr(items)) => std::mem::take(items),
                    _ => Vec::new(),
                };
                let mut properties = vec![Json::Obj(Obj(vec![
                    ("name".to_owned(), Json::Str(format!("{prefix}:bundled-wheel"))),
                    ("value".to_owned(), Json::str(directory)),
                ]))];
                properties.extend(info.properties);
                properties.extend(own);
                component.set("properties", Json::Arr(properties));
            }
            let reference = component.str("bom-ref").unwrap_or("").to_owned();
            let mut children = Vec::with_capacity(items.len());
            for (_, item) in items {
                children.push(match item {
                    Item::File(row) => file_component(&reference, row),
                    Item::Wheel(wheel) => {
                        let info = next_info();
                        let wheel = wheel.as_ref().map_err(|message| Error::Wheel(message.clone()))?;
                        bundled_wheel_component(wheel, prefix, &info.properties, info.supplier.as_ref())
                    }
                });
            }
            component.set("components", Json::Arr(children));
            components.push(Json::Obj(component));
        }
        let mut root = Obj::with_capacity(8);
        root.push("type", Json::str("application"));
        root.push("bom-ref", Json::str(self.root_ref.as_str()));
        root.push("name", Json::str(self.name.as_str()));
        root.push("version", self.version.as_deref().map_or(Json::Null, Json::str));
        root.push("purl", Json::str(self.root_ref.as_str()));
        root.push("components", Json::Arr(self.loose.iter().map(|row| file_component(&self.root_ref, row)).collect()));
        let mut properties = contributed_properties(&contributions.root_properties, prefix)?;
        if let Some(revision) = &facts.revision {
            properties.push(Json::Obj(Obj(vec![
                ("name".to_owned(), Json::Str(format!("{prefix}:vcs-commit"))),
                ("value".to_owned(), Json::str(revision.commit.as_str())),
            ])));
        }
        root.push("properties", Json::Arr(properties));
        components.extend(contributions.components);
        let (environment, environment_dependencies) = tool_components(facts);
        let mut tools = Vec::with_capacity(scripts.len() + environment.len() + contributions.tools.len());
        for (path, content) in scripts {
            let mut hasher = Hasher::new("sha256").expect("sha256");
            hasher.update(content);
            let link = self.identity.repository.as_ref().map(|repository| format!("{repository}/blob/{}/{path}", self.settings.default_branch));
            tools.push(script_tool(path, &to_hex(&hasher.finish()), self.version.as_deref(), link));
        }
        tools.extend(environment);
        tools.extend(contributions.tools);
        let formula = formulation("archive-build", &format!("build {} and this SBOM", self.name), &tools, &self.root_ref, facts)?;
        if let Some(supplier) = &self.settings.supplier {
            root.push("supplier", supplier.clone());
        }
        let mut metadata = Obj::with_capacity(7);
        metadata.push("timestamp", Json::Str(timestamp(facts.epoch)));
        metadata.push("lifecycles", Json::Arr(vec![Json::Obj(Obj(vec![("phase".to_owned(), Json::str("build"))]))]));
        metadata.push("tools", Json::Obj(Obj(vec![("components".to_owned(), Json::Arr(tools))])));
        metadata.push("component", Json::Obj(root));
        metadata.push(
            "properties",
            Json::Arr(vec![Json::Obj(Obj(vec![
                ("name".to_owned(), Json::Str(format!("{prefix}:{SBOM_FILE}"))),
                ("value".to_owned(), Json::Str(format!("{}.cdx.json", self.name))),
            ]))]),
        );
        if let Some(supplier) = &self.settings.supplier {
            metadata.push("manufacturer", supplier.clone());
            metadata.push("supplier", supplier.clone());
        }
        let mut direct = Vec::with_capacity(components.len());
        for component in &components {
            direct.push(Json::str(component.as_obj().and_then(|object| object.str("bom-ref")).ok_or_else(|| Error::Key("'bom-ref'".to_owned()))?));
        }
        let mut dependencies = vec![Json::Obj(Obj(vec![
            ("ref".to_owned(), Json::str(self.root_ref.as_str())),
            ("dependsOn".to_owned(), Json::Arr(direct)),
        ]))];
        dependencies.extend(vendored_dependencies(&components)?);
        dependencies.extend(environment_dependencies);
        dependencies.extend(contributions.dependencies);
        let mut body = Obj::with_capacity(4);
        body.push("metadata", Json::Obj(metadata));
        body.push("components", Json::Arr(components));
        body.push("dependencies", Json::Arr(dependencies));
        body.push("formulation", Json::Arr(vec![formula]));
        with_header(body, &self.identity.serial_namespace)
    }
}
