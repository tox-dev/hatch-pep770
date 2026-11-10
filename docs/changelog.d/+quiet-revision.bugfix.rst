A wheel built from an sdist no longer warns that git cannot read the source revision when the sdist names the
commit, as when uv builds it under the empty ``.git`` file it keeps in its cache.
