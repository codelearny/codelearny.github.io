---
title: MarkDown 基本语法
date: 2021-01-09 20:16:05
tags: [Java,C++,Python,JS,Mysql]
categories:
    - [DB,Mysql]
    - [Java,Spring,Spring Boot]
    - [Java,Spring,Spring Cloud]
    - [JS,Node]
    - [JS,VUE]
    - [JS,React]
    - [Network,HTTP]
    - [Network,TCP/IP]
    - [Python]
---
### 标题
    大标题
    ===
    小标题
    ---
    # 一级标题
    ## 二级标题
    ### 三级标题
    #### 四级标题
    ##### 五级标题
    ###### 六级标题
### 引用
    >this is a block
    >>this is another
    >>>段落的换行两个空格加回车  
    或者直接用空行分开
>this is a block
>>this is another
>>>段落的换行两个空格加回车  
或者直接用空行分开
### 列表
    1. 有序列表只需要1开头
    20. 其他数字不影响顺序
    13. cccc
    * 无序列表
        + 列表嵌套只需要加缩进
            - ffff
1. 有序列表只需要1开头
20. 其他数字不影响顺序
13. cccc
* 无序列表
    + 列表嵌套只需要加缩进
        - ffff

### 代码块
缩进四个空格表示代码块

        //代码块
三个`表示代码块，js为代码语言

<pre>
<code>```js</code>
console.log('hello')
<code>```</code>
</pre>

```js
console.log('hello')
```
### 分割线
    ***
***
    ---
---
### 字体效果
    *斜体*  _斜体_
*斜体*  _斜体_

    **粗体**  __粗体__
**粗体**  __粗体__

    ***粗体+斜体***
***粗体+斜体***

    ~~删除线~~
~~删除线~~

    `阴影`
`阴影`
### 表格
    name|age|tall|address
    --|:--:|:--|--:
    默认|居中|左对齐|右对齐
    black|22|188|a
name|age|tall|address
--|:--:|:--|--:
默认|居中|左对齐|右对齐
black|22|188|a
### 图片与链接
#### 链接
链接定义 `\[内容\](地址 "标题")`  
也可以直接用`<地址>`

    [example](https://codelearny.github.io/ "the description of this site") with description.
    [example](https://codelearny.github.io/) without title attribute.
    <https://codelearny.github.io/>
[example](https://codelearny.github.io/ "the description of this site") with description.  
[example](https://codelearny.github.io/) without title attribute.  
<https://codelearny.github.io/>

可以将链接地址设为变量`[标识]:地址 "标题"`  
定义时直接引用`[内容][标识]`

    [1]:https://github.com
    [my blog]:https://codelearny.github.io/ "我的博客"
    [This is my blog][my blog]
    [github][1]
[1]:https://github.com
[my blog]:https://codelearny.github.io/ "我的博客"
[This is my blog][my blog]  
[github][1]

#### 图片
图片定义和链接类似，以感叹号开头`![Alt Text](地址 "标题")`  
也可以使用变量`![Alt Text][标识])`

    ![说明](https://github.githubassets.com/favicons/favicon.png "提示文字")
    ![一个图片][2]
    [2]:/path/to/pic
![说明](https://github.githubassets.com/favicons/favicon.png "提示文字")
#### 锚点
锚点定义和链接定义类似 `[内容](#目标)`  
跳转的目标可以是各级标题  
也可以使用html标记的id属性`<span id="id">锚点目标</span>`  
`[内容](#id)`

    [跳转到标题](#标题)
    [跳转到列表](#列表)
[跳转到标题](#标题)  
[跳转到列表](#列表)
### 其它
Markdown支持html标签，可以直接在文档中使用
    
    <kbd>kbd</kbd>
<kbd>kbd</kbd>
Markdown使用\转义特殊字符
    
    \`转义\`
\`转义\`