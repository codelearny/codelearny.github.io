---
title: Vue项目搭建
date: 2021-07-05 11:33:51
tags: ['Vue','JavaScript']
---
## 基于Vue3.x的后台管理前端模板
> Vue vue-router vuex axios Stylus Echarts

├── config                     // 配置相关
├── public                     // 静态资源，不会被webpack编译
│   ├── favicon.ico            // 网站图标
│   └── index.html             // html编译入口
├── src                        // 源代码
│   ├── api                    // axios，后台接口封装
│   ├── assets                 // 静态资源，会被webpack编译
│   ├── components             // 功能组件
│   ├── directive              // 全局指令
│   ├── filtres                // 全局 filter
│   ├── icons                  // 项目所有 svg icons
│   ├── lang                   // 国际化 language
│   ├── mock                   // 项目mock 模拟数据
│   ├── router                 // vue-router，路由配置
│   ├── store                  // vuex，store配置
│   ├── styles                 // 全局样式
│   ├── utils                  // 通用工具模块
│   ├── vendor                 // 公用vendor
│   ├── views                  // 视图组件
│   ├── App.vue                // vue入口
│   ├── main.js                // 项目总入口，加载组件 初始化等
│   └── permission.js          // 权限管理
├── static                     // 第三方不打包资源
│   └── Tinymce                // 富文本
├── babel.config.js            // babel 配置
├── eslintrc.js                // eslint 配置项
├── .gitignore                 // git 忽略项
├── README.md                  // 项目的说明文档
├── package.json               // node包管理
├── package-lock.json          // node包管理
└── vue.config.js              // 构建相关，webpack

