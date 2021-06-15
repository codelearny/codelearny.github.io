---
title: editorconfig
date: 2021-06-15 10:56:59
tags: [editorconfig,engineering]
---
[EditorConfig官网](https://editorconfig.org/)
> `EditorConfig`有助于在不同的编辑器和IDE中为在同一项目上工作的多个开发人员保持一致的编码样式。`EditorConfig`项目由一个用于定义编码样式的文件格式和一组文本编辑器插件组成，这些插件使编辑器能够读取文件格式并遵循定义的样式。`EditorConfig`文件易于阅读，并且与版本控制系统配合良好。

`VS Code`安装对应插件
编写`.editorconfig`文件
```bash
# top-most EditorConfig file
root = true

# Unix-style newlines with a newline ending every file
[*]
end_of_line = lf
insert_final_newline = true

# Matches multiple files with brace expansion notation
# Set default charset
[*.{js,py}]
charset = utf-8

# 4 space indentation
[*.py]
indent_style = space
indent_size = 4

# Tab indentation (no size specified)
[Makefile]
indent_style = tab

# Indentation override for all JS under lib directory
[lib/**.js]
indent_style = space
indent_size = 2

# Matches the exact files either package.json or .travis.yml
[{package.json,.travis.yml}]
indent_style = space
indent_size = 2
```