<h1 align="center">
    <a href="https://github.com/SpriteOvO/sigmatch"><img src="/assets/logo.svg" alt="logo" width="128"></a>
    <br>
    sigmatch
</h1>
<p align="center">Modern C++ 20 Signature Match / Search Library</p>
<p align="center">
    <a href="https://github.com/SpriteOvO/sigmatch/actions/workflows/windows.yml">
        <img src="https://github.com/SpriteOvO/sigmatch/actions/workflows/windows.yml/badge.svg"/>
    </a>
    <a href="https://github.com/SpriteOvO/sigmatch/compare">
        <img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg"/>
    </a>
    <a href="/LICENSE">
        <img src="https://img.shields.io/badge/license-Apache--2.0-yellow.svg"/>
    </a>
</p>

## ✨ Features

- 🍃 Header-only, no dependencies, no exceptions.
- ☕ Compile-time literal signature string parsing.
- ❄️ Supports full-byte wildcards (`??` or `**`) and semi-byte wildcards (`1?` or `*B`).
- 🚀 Supports blocking (chunking) and multi-threaded for fast search.
- 🎯 Supports searching in the current process, external processes and files.
- 🍄 Customizable `reader` and `target` allow you to search on more targets (e.g. network traffic packets).

## 🌠 Examples

A quick example:

```cpp
using namespace sigmatch_literals;

sigmatch::this_process_target target;
sigmatch::search_result result = target.in_module("**module_name**").search("1A ?? 3C ** 5* ?F"_sig);
for (const std::byte *address : result.matches()) {
    std::cout << "matched: " << address << '\n';
}
```

See [/examples](/examples) for more.

## 🍰 Todo

- [ ] Complete CI for testing and documentation deployment.
- [ ] Host the documentation on GitHub Pages.
- [ ] Statistical tests coverage.
- [ ] Complete benchmarks.
- [ ] Test compilers other than **MSVC**.
- [ ] Implement class `executable_file_target`.
- [ ] Port to **Linux**.

## 📜 License

**sigmatch** is licensed under the [Apache-2.0 License](/LICENSE).
