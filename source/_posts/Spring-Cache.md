---
title: Spring Cache
date: 2021-03-08 09:11:50
tags: [Spring,Cache]
categories:
    - [Java,Spring,Spring Cache]
---
# Spring Cache 设计原理
## Spring Cache API
`Spring Cache API` 相关接口位于`spring-context`包，相对路径`org.springframework.cache`下。
核心接口 `org.springframework.cache.Cache` 定义通用缓存操作的接口，`org.springframework.cache.CacheManager` 缓存管理核心SPI，允许检索命名缓存区域
### Cache
该接口是对缓存操作的抽象，主要操作为 get put evict，可根据具体缓存实现对应方法
```java
public interface Cache {
	// 缓存名称
	String getName();
	// 返回底层的缓存对象
	Object getNativeCache();
	// 返回缓存键对应的值，使用 ValueWrapper 接口包装
	@Nullable
	ValueWrapper get(Object key);
	// 返回值自动转换为指定类型
	@Nullable
	<T> T get(Object key, @Nullable Class<T> type);
	// 用于同步查询缓存，同步保证由具体实现负责
	@Nullable
	<T> T get(Object key, Callable<T> valueLoader);
	// 放置缓存
	void put(Object key, @Nullable Object value);
	// 指定 key 不存在，放置新的 value 否则返回原有 value
	@Nullable
	default ValueWrapper putIfAbsent(Object key, @Nullable Object value) {
		ValueWrapper existingValue = get(key);
		if (existingValue == null) {
			put(key, value);
		}
		return existingValue;
	}
	// 删除指定缓存
	void evict(Object key);
	// 删除指定缓存
	default boolean evictIfPresent(Object key) {
		evict(key);
		return false;
	}
	// 清空缓存
	void clear();
	// 清空缓存
	default boolean invalidate() {
		clear();
		return false;
	}
}
```
以 Redis 缓存实现为例
```java
public class RedisCache extends AbstractValueAdaptingCache {

	private static final byte[] BINARY_NULL_VALUE = RedisSerializer.java().serialize(NullValue.INSTANCE);
	// 缓存名称
	private final String name;
	// redis 操作的实现类
	private final RedisCacheWriter cacheWriter;
	// reids 配置
	private final RedisCacheConfiguration cacheConfig;
	// DefaultFormattingConversionService spring 提供的类型转换能力
	private final ConversionService conversionService;

	// 实际查找实现
	@Override
	protected Object lookup(Object key) {
		// 从 redis 中检索
		byte[] value = cacheWriter.get(name, createAndConvertCacheKey(key));
		if (value == null) {
			return null;
		}
		// 反序列化
		return deserializeCacheValue(value);
	}

	// 返回缓存名称
	@Override
	public String getName() {
		return name;
	}

	// 返回底层缓存实例
	@Override
	public RedisCacheWriter getNativeCache() {
		return this.cacheWriter;
	}

	// get 实现，使用 synchronized 实现同步
	@Override
	@SuppressWarnings("unchecked")
	public synchronized <T> T get(Object key, Callable<T> valueLoader) {
		// 缓存中查询
		ValueWrapper result = get(key);
		// 缓存命中直接返回
		if (result != null) {
			return (T) result.get();
		}
		// 执行取值逻辑
		T value = valueFromLoader(key, valueLoader);
		// 放置缓存
		put(key, value);
		return value;
	}

	// put 实现
	@Override
	public void put(Object key, @Nullable Object value) {
		// 空值处理
		Object cacheValue = preProcessCacheValue(value);
		if (!isAllowNullValues() && cacheValue == null) {
			throw new IllegalArgumentException(String.format("Cache '%s' does not allow 'null' values. Avoid storing null via '@Cacheable(unless=\"#result == null\")' or configure RedisCache to allow 'null' via RedisCacheConfiguration.", name));
		}
		// redis 操作
		cacheWriter.put(name, createAndConvertCacheKey(key), serializeCacheValue(cacheValue), cacheConfig.getTtl());
	}

	// putIfAbsent 实现
	@Override
	public ValueWrapper putIfAbsent(Object key, @Nullable Object value) {
		// 空值处理
		Object cacheValue = preProcessCacheValue(value);
		if (!isAllowNullValues() && cacheValue == null) {
			return get(key);
		}
		// redis 操作
		byte[] result = cacheWriter.putIfAbsent(name, createAndConvertCacheKey(key), serializeCacheValue(cacheValue), cacheConfig.getTtl());
		if (result == null) {
			return null;
		}
		return new SimpleValueWrapper(fromStoreValue(deserializeCacheValue(result)));
	}

	// evict 实现
	@Override
	public void evict(Object key) {
		// redis 操作
		cacheWriter.remove(name, createAndConvertCacheKey(key));
	}

	// clear 实现
	@Override
	public void clear() {
		// 类型转换
		byte[] pattern = conversionService.convert(createCacheKey("*"), byte[].class);
		// redis 操作
		cacheWriter.clean(name, pattern);
	}
}
```

### CacheManager
缓存管理器抽象，根据具体缓存实现
```java
public interface CacheManager {

	// 根据名称获得缓存实例
	Cache getCache(String name);

	// 返回该缓存管理器下的所有缓存名称
	Collection<String> getCacheNames();
}
```
以 Redis 缓存管理器为例
```java
public abstract class AbstractCacheManager implements CacheManager, InitializingBean {	
	// 本地缓存 name -> Cache
	private final ConcurrentMap<String, Cache> cacheMap = new ConcurrentHashMap<>(16);
	// 保存的缓存名称
	private volatile Set<String> cacheNames = Collections.emptySet();

	@Override
	@Nullable
	public Cache getCache(String name) {
		// 本地缓存命中直接返回
		Cache cache = this.cacheMap.get(name);
		if (cache != null) {
			return cache;
		}

		// 子类实现，创建缓存实例
		Cache missingCache = getMissingCache(name);
		if (missingCache != null) {
			// 创建操作同步
			synchronized (this.cacheMap) {
				cache = this.cacheMap.get(name);
				if (cache == null) {
					cache = decorateCache(missingCache);
					this.cacheMap.put(name, cache);
					updateCacheNames(name);
				}
			}
		}
		return cache;
	}
}
public class RedisCacheManager extends AbstractTransactionSupportingCacheManager {
	// 创建缓存实例
	@Override
	protected RedisCache getMissingCache(String name) {
		return allowInFlightCacheCreation ? createRedisCache(name, defaultCacheConfig) : null;
	}
	// 实例化 RedisCache
	protected RedisCache createRedisCache(String name, @Nullable RedisCacheConfiguration cacheConfig) {
		return new RedisCache(name, cacheWriter, cacheConfig != null ? cacheConfig : defaultCacheConfig);
	}
}
```


## 缓存注解原理
### @EnableCaching
使用`@EnableCaching` 可以开启注解支持，该注解导入了一个`CachingConfigurationSelector`，根据注解的mode属性，导入相应的配置类
```java
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(CachingConfigurationSelector.class)
public @interface EnableCaching {

	/**
	 * 指定代理类型，mode()设置为AdviceMode.PROXY时生效，影响所有Spring管理的Bean，默认使用jdk动态代理，true代表使用CGLIB代理
	 */
	boolean proxyTargetClass() default false;
      
	/**
	 * 指定缓存如何生效，默认使用动态代理方式，可升级为静态织入AdviceMode.ASPECTJ
	 */
	AdviceMode mode() default AdviceMode.PROXY;

	/**
	 * 指定缓存相关通知的执行顺序，当连接点存在多个通知时
	 */
	int order() default Ordered.LOWEST_PRECEDENCE;
}
```
### CachingConfigurationSelector
`CachingConfigurationSelector`实现了`ImportSelector`接口，可以获得注解元数据，根据元数据导入对应配置类。
默认导入`AutoProxyRegistrar`和`ProxyCachingConfiguration`
```java
public class CachingConfigurationSelector extends AdviceModeImportSelector<EnableCaching> {

	private static final String PROXY_JCACHE_CONFIGURATION_CLASS =	"org.springframework.cache.jcache.config.ProxyJCacheConfiguration";

	private static final String CACHE_ASPECT_CONFIGURATION_CLASS_NAME = "org.springframework.cache.aspectj.AspectJCachingConfiguration";

	private static final String JCACHE_ASPECT_CONFIGURATION_CLASS_NAME =	"org.springframework.cache.aspectj.AspectJJCacheConfiguration";

   // jsr-107规范
	private static final boolean jsr107Present;
   // jcache实现
	private static final boolean jcacheImplPresent;

	static {
		ClassLoader classLoader = CachingConfigurationSelector.class.getClassLoader();
		jsr107Present = ClassUtils.isPresent("javax.cache.Cache", classLoader);
		jcacheImplPresent = ClassUtils.isPresent(PROXY_JCACHE_CONFIGURATION_CLASS, classLoader);
	}

	/**
	 * 根据mode决定导入的类
	 */
	@Override
	public String[] selectImports(AdviceMode adviceMode) {
		switch (adviceMode) {
			case PROXY:
				return getProxyImports();
			case ASPECTJ:
				return getAspectJImports();
			default:
				return null;
		}
	}

	/**
	 * 导入 `AutoProxyRegistrar` 和 `ProxyCachingConfiguration`
	 */
	private String[] getProxyImports() {
		List<String> result = new ArrayList<>(3);
		result.add(AutoProxyRegistrar.class.getName());
		result.add(ProxyCachingConfiguration.class.getName());
		// 根据对应类是否存在判断是否加载jsr规范的自动配置类
		if (jsr107Present && jcacheImplPresent) {
			result.add(PROXY_JCACHE_CONFIGURATION_CLASS);
		}
		return StringUtils.toStringArray(result);
	}

	/**
	 * AdviceMode#ASPECTJ 配置类
	 */
	private String[] getAspectJImports() {
		List<String> result = new ArrayList<>(2);
		result.add(CACHE_ASPECT_CONFIGURATION_CLASS_NAME);
		if (jsr107Present && jcacheImplPresent) {
			result.add(JCACHE_ASPECT_CONFIGURATION_CLASS_NAME);
		}
		return StringUtils.toStringArray(result);
	}

}
```
### `AutoProxyRegistrar`
自动代理创建器注册器，用于在容器中注册一个`AbstractAutoProxyCreator`，通常是`AnnotationAwareAspectJAutoProxyCreator`，它是一个`SmartInstantiationAwareBeanPostProcessor`，在bean注入或者初始化化之后返回代理后的实例。构造代理对象时，会从容器中查找符合条件的通知器`Advisor`应用到代理对象，从而实现缓存相关功能的实现。

### `ProxyCachingConfiguration` extends `AbstractCachingConfiguration`
缓存代理功能组件配置，主要实现以下功能
  1. 注入`CachingConfigurer`
  2. 声明`AnnotationCacheOperationSource`
  3. 声明`CacheInterceptor`
  4. 声明`BeanFactoryCacheOperationSourceAdvisor`
     
#### CachingConfigurer
缓存配置自定义，可实现该接口自定义缓存相关的`CacheManager`，`CacheResolver`，`KeyGenerator`，`CacheErrorHandler`，也可以继承`CachingConfigurerSupport`，选择实现部分功能
#### AnnotationCacheOperationSource
实现接口`CacheOperationSource`，给`CacheInterceptor`拦截器提供缓存操作所需的属性，该实现类从`Spring`缓存相关注解中读取元数据，默认内置`SpringCacheAnnotationParser`从方法或类上解析注解的元数据并缓存
```java
public class AnnotationCacheOperationSource extends AbstractFallbackCacheOperationSource implements Serializable {
   // 标识只支持public方法
	private final boolean publicMethodsOnly;

	private final Set<CacheAnnotationParser> annotationParsers;

	/**
    * 默认构造方法，只支持public方法
	 */
	public AnnotationCacheOperationSource() {
		this(true);
	}

	/**
	 * 默认使用 SpringCacheAnnotationParser 注解解析器
	 */
	public AnnotationCacheOperationSource(boolean publicMethodsOnly) {
		this.publicMethodsOnly = publicMethodsOnly;
		this.annotationParsers = Collections.singleton(new SpringCacheAnnotationParser());
	}

	public AnnotationCacheOperationSource(CacheAnnotationParser annotationParser) {
		this.publicMethodsOnly = true;
		Assert.notNull(annotationParser, "CacheAnnotationParser must not be null");
		this.annotationParsers = Collections.singleton(annotationParser);
	}

	public AnnotationCacheOperationSource(CacheAnnotationParser... annotationParsers) {
		this.publicMethodsOnly = true;
		Assert.notEmpty(annotationParsers, "At least one CacheAnnotationParser needs to be specified");
		this.annotationParsers = new LinkedHashSet<>(Arrays.asList(annotationParsers));
	}

	public AnnotationCacheOperationSource(Set<CacheAnnotationParser> annotationParsers) {
		this.publicMethodsOnly = true;
		Assert.notEmpty(annotationParsers, "At least one CacheAnnotationParser needs to be specified");
		this.annotationParsers = annotationParsers;
	}
   // 判断注解解析器是否支持指定类
	@Override
	public boolean isCandidateClass(Class<?> targetClass) {
		for (CacheAnnotationParser parser : this.annotationParsers) {
			if (parser.isCandidateClass(targetClass)) {
				return true;
			}
		}
		return false;
	}
   // 解析类，委托解析器执行
	@Override
	@Nullable
	protected Collection<CacheOperation> findCacheOperations(Class<?> clazz) {
		return determineCacheOperations(parser -> parser.parseCacheAnnotations(clazz));
	}
   // 解析方法，委托解析器执行
	@Override
	@Nullable
	protected Collection<CacheOperation> findCacheOperations(Method method) {
		return determineCacheOperations(parser -> parser.parseCacheAnnotations(method));
	}

	/**
	 * 通过解析器分析注解信息，封装为 CacheOperation 元数据类
	 */
	@Nullable
	protected Collection<CacheOperation> determineCacheOperations(CacheOperationProvider provider) {
		Collection<CacheOperation> ops = null;
		for (CacheAnnotationParser parser : this.annotationParsers) {
			Collection<CacheOperation> annOps = provider.getCacheOperations(parser);
			if (annOps != null) {
				if (ops == null) {
					ops = annOps;
				}
				else {
					Collection<CacheOperation> combined = new ArrayList<>(ops.size() + annOps.size());
					combined.addAll(ops);
					combined.addAll(annOps);
					ops = combined;
				}
			}
		}
		return ops;
	}

}

```
实际的解析动作由`SpringCacheAnnotationParser`完成，解析对应注解上的属性，封装为`CacheableOperation`
```java
public class SpringCacheAnnotationParser implements CacheAnnotationParser, Serializable {
	// 支持的缓存操作注解
	private static final Set<Class<? extends Annotation>> CACHE_OPERATION_ANNOTATIONS = new LinkedHashSet<>(8);
	// 初始化支持的操作注解
	static {
		CACHE_OPERATION_ANNOTATIONS.add(Cacheable.class);
		CACHE_OPERATION_ANNOTATIONS.add(CacheEvict.class);
		CACHE_OPERATION_ANNOTATIONS.add(CachePut.class);
		CACHE_OPERATION_ANNOTATIONS.add(Caching.class);
	}
	// 分析目标类上是否有指定的注解
	@Override
	public boolean isCandidateClass(Class<?> targetClass) {
		return AnnotationUtils.isCandidateClass(targetClass, CACHE_OPERATION_ANNOTATIONS);
	}
	// 分析类
	@Override
	@Nullable
	public Collection<CacheOperation> parseCacheAnnotations(Class<?> type) {
		DefaultCacheConfig defaultConfig = new DefaultCacheConfig(type);
		return parseCacheAnnotations(defaultConfig, type);
	}
	// 分析方法，如果类上使用了 `@CacheConfig` 可设置类级别的默认设置
	@Override
	@Nullable
	public Collection<CacheOperation> parseCacheAnnotations(Method method) {
		DefaultCacheConfig defaultConfig = new DefaultCacheConfig(method.getDeclaringClass());
		return parseCacheAnnotations(defaultConfig, method);
	}
	// 解析缓存注解
	@Nullable
	private Collection<CacheOperation> parseCacheAnnotations(DefaultCacheConfig cachingConfig, AnnotatedElement ae) {
		Collection<CacheOperation> ops = parseCacheAnnotations(cachingConfig, ae, false);
		if (ops != null && ops.size() > 1) {
			// 解析出多个注解，本类的覆盖接口上的
			Collection<CacheOperation> localOps = parseCacheAnnotations(cachingConfig, ae, true);
			if (localOps != null) {
				return localOps;
			}
		}
		return ops;
	}
	// 解析缓存注解， localOnly 指示是否本类优先
	@Nullable
	private Collection<CacheOperation> parseCacheAnnotations(DefaultCacheConfig cachingConfig, AnnotatedElement ae, boolean localOnly) {
		Collection<? extends Annotation> anns = (localOnly ?
				// 不向上递归查找
				AnnotatedElementUtils.getAllMergedAnnotations(ae, CACHE_OPERATION_ANNOTATIONS) :
				// 递归查找
				AnnotatedElementUtils.findAllMergedAnnotations(ae, CACHE_OPERATION_ANNOTATIONS));
		if (anns.isEmpty()) {
			// 没有找到注解直接返回null
			return null;
		}

		final Collection<CacheOperation> ops = new ArrayList<>(1);
		// 解析Cacheable
		anns.stream().filter(ann -> ann instanceof Cacheable).forEach(ann -> ops.add(parseCacheableAnnotation(ae, cachingConfig, (Cacheable) ann)));
		// 解析CacheEvict
		anns.stream().filter(ann -> ann instanceof CacheEvict).forEach(ann -> ops.add(parseEvictAnnotation(ae, cachingConfig, (CacheEvict) ann)));
		// 解析CachePut
		anns.stream().filter(ann -> ann instanceof CachePut).forEach(ann -> ops.add(parsePutAnnotation(ae, cachingConfig, (CachePut) ann)));
		// 解析Caching
		anns.stream().filter(ann -> ann instanceof Caching).forEach(ann -> parseCachingAnnotation(ae, cachingConfig, (Caching) ann, ops));
		return ops;
	}
	// 注解属性大部分一样，使用建造者模式
	// cacheNames 缓存名
	// condition 条件 SpEL表达式
	// unless 否决 SpEL表达式
	// key 缓存键 SpEL表达式 不可同时指定 key 和 keyGenerator
	// keyGenerator 缓存键生成器的bean名称
	// cacheManager 缓存管理器 不可同时指定 cacheManager 和 cacheResolver
	// cacheResolver 缓存解析器
	private CacheableOperation parseCacheableAnnotation(AnnotatedElement ae, DefaultCacheConfig defaultConfig, Cacheable cacheable) {

		CacheableOperation.Builder builder = new CacheableOperation.Builder();

		builder.setName(ae.toString());
		builder.setCacheNames(cacheable.cacheNames());
		builder.setCondition(cacheable.condition());
		builder.setUnless(cacheable.unless());
		builder.setKey(cacheable.key());
		builder.setKeyGenerator(cacheable.keyGenerator());
		builder.setCacheManager(cacheable.cacheManager());
		builder.setCacheResolver(cacheable.cacheResolver());
		builder.setSync(cacheable.sync());

		defaultConfig.applyDefault(builder);
		CacheableOperation op = builder.build();
		validateCacheOperation(ae, op);

		return op;
	}

	private CacheEvictOperation parseEvictAnnotation(AnnotatedElement ae, DefaultCacheConfig defaultConfig, CacheEvict cacheEvict) {

		CacheEvictOperation.Builder builder = new CacheEvictOperation.Builder();

		builder.setName(ae.toString());
		builder.setCacheNames(cacheEvict.cacheNames());
		builder.setCondition(cacheEvict.condition());
		builder.setKey(cacheEvict.key());
		builder.setKeyGenerator(cacheEvict.keyGenerator());
		builder.setCacheManager(cacheEvict.cacheManager());
		builder.setCacheResolver(cacheEvict.cacheResolver());
		builder.setCacheWide(cacheEvict.allEntries());
		builder.setBeforeInvocation(cacheEvict.beforeInvocation());

		defaultConfig.applyDefault(builder);
		CacheEvictOperation op = builder.build();
		validateCacheOperation(ae, op);

		return op;
	}

	private CacheOperation parsePutAnnotation(AnnotatedElement ae, DefaultCacheConfig defaultConfig, CachePut cachePut) {

		CachePutOperation.Builder builder = new CachePutOperation.Builder();

		builder.setName(ae.toString());
		builder.setCacheNames(cachePut.cacheNames());
		builder.setCondition(cachePut.condition());
		builder.setUnless(cachePut.unless());
		builder.setKey(cachePut.key());
		builder.setKeyGenerator(cachePut.keyGenerator());
		builder.setCacheManager(cachePut.cacheManager());
		builder.setCacheResolver(cachePut.cacheResolver());

		defaultConfig.applyDefault(builder);
		CachePutOperation op = builder.build();
		validateCacheOperation(ae, op);

		return op;
	}
	// 复合注解 分别解析
	private void parseCachingAnnotation(AnnotatedElement ae, DefaultCacheConfig defaultConfig, Caching caching, Collection<CacheOperation> ops) {

		Cacheable[] cacheables = caching.cacheable();
		for (Cacheable cacheable : cacheables) {
			ops.add(parseCacheableAnnotation(ae, defaultConfig, cacheable));
		}
		CacheEvict[] cacheEvicts = caching.evict();
		for (CacheEvict cacheEvict : cacheEvicts) {
			ops.add(parseEvictAnnotation(ae, defaultConfig, cacheEvict));
		}
		CachePut[] cachePuts = caching.put();
		for (CachePut cachePut : cachePuts) {
			ops.add(parsePutAnnotation(ae, defaultConfig, cachePut));
		}
	}

}
```

#### CacheInterceptor
实现AOP联盟接口`MethodInterceptor`，用于使用通用`Spring`缓存基础结构的声明式缓存管理。继承自`CacheAspectSupport`，包含了与`Spring`底层缓存API的集成。
主要操作流程在 `CacheAspectSupport.execute`
```java
public class CacheInterceptor extends CacheAspectSupport implements MethodInterceptor, Serializable {

	@Override
	@Nullable
	public Object invoke(final MethodInvocation invocation) throws Throwable {
		Method method = invocation.getMethod();

		CacheOperationInvoker aopAllianceInvoker = () -> {
			try {
				// 调用 MethodInvocation 处理
				return invocation.proceed();
			}
			catch (Throwable ex) {
				throw new CacheOperationInvoker.ThrowableWrapper(ex);
			}
		};

		try {
			// 调用CacheAspectSupport.execute
			return execute(aopAllianceInvoker, invocation.getThis(), method, invocation.getArguments());
		}
		catch (CacheOperationInvoker.ThrowableWrapper th) {
			throw th.getOriginal();
		}
	}

}
```
`CacheAspectSupport`，该类包含与`Spring`底层缓存API的集成，使用策略设计模式。`CacheOperationSource`用于确定缓存操作，`KeyGenerator`将构建缓存键，`CacheResolver`将解析要使用的实际缓存。`BeanFactoryAware`接口自动注入`BeanFactory`。
```java
public abstract class CacheAspectSupport extends AbstractCacheInvoker
		implements BeanFactoryAware, InitializingBean, SmartInitializingSingleton {
	// CacheOperation 元数据的缓存
	private final Map<CacheOperationCacheKey, CacheOperationMetadata> metadataCache = new ConcurrentHashMap<>(1024);
	// SpEL表达式解析的工具类
	private final CacheOperationExpressionEvaluator evaluator = new CacheOperationExpressionEvaluator();
	// 此处可配置为 CompositeCacheOperationSource ，用于迭代多个 CacheOperationSource
	// 自动配置类自动注入 AnnotationCacheOperationSource
	private CacheOperationSource cacheOperationSource;
	// 缓存键生成器，可通过 CachingConfigurer 自定义
	private SingletonSupplier<KeyGenerator> keyGenerator = SingletonSupplier.of(SimpleKeyGenerator::new);
	// 缓存操作解析类，根据缓存操作上下文确定缓存实例
	private SingletonSupplier<CacheResolver> cacheResolver;
	// 自动注入bean工厂
	private BeanFactory beanFactory;
	// 标识 是否初始化，在 SmartInitializingSingleton.afterSingletonsInstantiated 声明周期函数中置为 true
	private boolean initialized = false;
	// 
	protected Object execute(CacheOperationInvoker invoker, Object target, Method method, Object[] args) {
		if (this.initialized) {
			// 拿到代理类的最终目标类
			Class<?> targetClass = getTargetClass(target);
			// 得到 AnnotationCacheOperationSource
			CacheOperationSource cacheOperationSource = getCacheOperationSource();
			if (cacheOperationSource != null) {
				// 解析方法上的 缓存操作注解，封装为 CacheOperation
				Collection<CacheOperation> operations = cacheOperationSource.getCacheOperations(method, targetClass);
				if (!CollectionUtils.isEmpty(operations)) {
					// 相关操作封装为 CacheOperationContexts 上下文
					return execute(invoker, method,	new CacheOperationContexts(operations, method, args, target, targetClass));
				}
			}
		}
		return invoker.invoke();
	}
	// 
	private Object execute(final CacheOperationInvoker invoker, Method method, CacheOperationContexts contexts) {
		// 多线程同步调用
		if (contexts.isSynchronized()) {
			CacheOperationContext context = contexts.get(CacheableOperation.class).iterator().next();
			// 计算 condition 表达式 是否通过
			if (isConditionPassing(context, CacheOperationExpressionEvaluator.NO_RESULT)) {
				// 生成缓存key
				Object key = generateKey(context, CacheOperationExpressionEvaluator.NO_RESULT);
				// 通过 CacheResolver 解析缓存，默认使用注解配置的 cacheNames 通过 CacheManager.getCache 得到
				Cache cache = context.getCaches().iterator().next();
				try {
					// invoker 执行原始方法，得到返回值，调用具体的 Cache 实现缓存操作，同步操作由具体实现负责
					// 方法返回值支持 Optional
					return wrapCacheValue(method, handleSynchronizedGet(invoker, key, cache));
				}
				catch (Cache.ValueRetrievalException ex) {
					// Directly propagate ThrowableWrapper from the invoker,
					// or potentially also an IllegalArgumentException etc.
					ReflectionUtils.rethrowRuntimeException(ex.getCause());
				}
			}
			else {
				// 无需缓存，直接调用底层方法
				return invokeOperation(invoker);
			}
		}

		// 执行方法调用前的缓存清理， CacheEvict 注解 beforeInvocation 设置为 true
		processCacheEvicts(contexts.get(CacheEvictOperation.class), true, CacheOperationExpressionEvaluator.NO_RESULT);

		// 检查是否命中 Cacheable 缓存
		Cache.ValueWrapper cacheHit = findCachedItem(contexts.get(CacheableOperation.class));

		// Cacheable 缓存未命中， 收集需要放置到缓存的操作
		List<CachePutRequest> cachePutRequests = new LinkedList<>();
		if (cacheHit == null) {
			collectPutRequests(contexts.get(CacheableOperation.class), CacheOperationExpressionEvaluator.NO_RESULT, cachePutRequests);
		}

		Object cacheValue;
		Object returnValue;
		// Cacheable 缓存命中， 并且没有生效的 CachePut
		if (cacheHit != null && !hasCachePut(contexts)) {
			// 直接使用命中的缓存值
			cacheValue = cacheHit.get();
			returnValue = wrapCacheValue(method, cacheValue);
		}
		else {
			// 执行目标方法获得返回值
			returnValue = invokeOperation(invoker);
			cacheValue = unwrapReturnValue(returnValue);
		}

		// 收集显示的 CachePut 操作
		collectPutRequests(contexts.get(CachePutOperation.class), cacheValue, cachePutRequests);

		// 执行收集后的缓存放置操作
		for (CachePutRequest cachePutRequest : cachePutRequests) {
			cachePutRequest.apply(cacheValue);
		}

		// 执行方法调用前的缓存清理， CacheEvict 注解 beforeInvocation 设置为 false
		processCacheEvicts(contexts.get(CacheEvictOperation.class), false, cacheValue);

		return returnValue;
	}
}
```

#### BeanFactoryCacheOperationSourceAdvisor
见名知意，通知器，提供BeanFactory能力，CacheOperationSource能力，通知器主要能力由`AbstractBeanFactoryPointcutAdvisor`提供，提供切面实现`CacheOperationSourcePointcut`，再委托给`AnnotationCacheOperationSource`解析是否存在缓存相关注解
```java
public class BeanFactoryCacheOperationSourceAdvisor extends AbstractBeanFactoryPointcutAdvisor {
	// 自动配置注入 AnnotationCacheOperationSource
	private CacheOperationSource cacheOperationSource;
	// 类似适配器的功能，提供切面操作
	private final CacheOperationSourcePointcut pointcut = new CacheOperationSourcePointcut() {
		@Override
		@Nullable
		protected CacheOperationSource getCacheOperationSource() {
			return cacheOperationSource;
		}
	};

	public void setCacheOperationSource(CacheOperationSource cacheOperationSource) {
		this.cacheOperationSource = cacheOperationSource;
	}

	public void setClassFilter(ClassFilter classFilter) {
		this.pointcut.setClassFilter(classFilter);
	}

	@Override
	public Pointcut getPointcut() {
		return this.pointcut;
	}

}
```
`AbstractBeanFactoryPointcutAdvisor`是一个`PointcutAdvisor`，由切面驱动的通知器，实现了`BeanFactoryAware`接口提供bean工厂的能力，允许将任何`Advice`配置为`BeanFactory`中的bean。指定bean的名称可以减少初始化的耦合，在切入点实际匹配之前不初始化`Advice`。
```java
public abstract class AbstractBeanFactoryPointcutAdvisor extends AbstractPointcutAdvisor implements BeanFactoryAware {
	// 通知bean的名称，用于从 BeanFactory 中获取通知
	private String adviceBeanName;
	// BeanFactoryAware 提供
	private BeanFactory beanFactory;
	// 通知
	private transient volatile Advice advice;
	// advice 的监视器对象，用于同步
	private transient volatile Object adviceMonitor = new Object();

	/**
	 * 直接指定通知实例，使用时无需从bean工厂查找
	 * 自动配置直接设置 CacheInterceptor
	 */
	public void setAdvice(Advice advice) {
		synchronized (this.adviceMonitor) {
			this.advice = advice;
		}
	}
	// 自动配置直接获取 CacheInterceptor
	@Override
	public Advice getAdvice() {
		Advice advice = this.advice;
		if (advice != null) {
			return advice;
		}
		//下略。。。
	}

}

```
## Spring Boot 自动配置
`Spring Boot`自动配置文件`spring-boot-autoconfigure-x.x.x.jar`中的 META-INF\spring.factories 可以找到缓存自动配置类`CacheAutoConfiguration`，在使用`@EnableCaching`注解后
开启
```java
@Configuration(proxyBeanMethods = false)
@ConditionalOnClass(CacheManager.class)
@ConditionalOnBean(CacheAspectSupport.class)
@ConditionalOnMissingBean(value = CacheManager.class, name = "cacheResolver")
@EnableConfigurationProperties(CacheProperties.class)
@AutoConfigureAfter({ CouchbaseDataAutoConfiguration.class, HazelcastAutoConfiguration.class, HibernateJpaAutoConfiguration.class, RedisAutoConfiguration.class })
@Import({ CacheConfigurationImportSelector.class, CacheManagerEntityManagerFactoryDependsOnPostProcessor.class })
public class CacheAutoConfiguration {
	// 自定义 CacheManager
	@Bean
	@ConditionalOnMissingBean
	public CacheManagerCustomizers cacheManagerCustomizers(ObjectProvider<CacheManagerCustomizer<?>> customizers) {
		return new CacheManagerCustomizers(customizers.orderedStream().collect(Collectors.toList()));
	}
	// 确保 CacheManager 存在，如不存在提供可读性更好的异常提示
	@Bean
	public CacheManagerValidator cacheAutoConfigurationValidator(CacheProperties cacheProperties, ObjectProvider<CacheManager> cacheManager) {
		return new CacheManagerValidator(cacheProperties, cacheManager);
	}
	// Spring data jpa 环境下，声明实体管理器工厂 依赖 cacheManager
	@ConditionalOnClass(LocalContainerEntityManagerFactoryBean.class)
	@ConditionalOnBean(AbstractEntityManagerFactoryBean.class)
	static class CacheManagerEntityManagerFactoryDependsOnPostProcessor extends EntityManagerFactoryDependsOnPostProcessor {

		CacheManagerEntityManagerFactoryDependsOnPostProcessor() {
			super("cacheManager");
		}

	}


	// 导入各种缓存类型对应的配置类
	static class CacheConfigurationImportSelector implements ImportSelector {

		@Override
		public String[] selectImports(AnnotationMetadata importingClassMetadata) {
			CacheType[] types = CacheType.values();
			String[] imports = new String[types.length];
			for (int i = 0; i < types.length; i++) {
				imports[i] = CacheConfigurations.getConfigurationClass(types[i]);
			}
			return imports;
		}

	}

}

```