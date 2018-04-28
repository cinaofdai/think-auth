<?php
/**
 * Created by dailinlin.
 * Date: 2017/10/10 15:21
 * for: 权限管理操作类
 */

namespace think\auth;


use think\auth\helper\Data;
use think\Config;
use think\Db;
use think\Validate;

class AuthManager
{
    /**
     * @var object 对象实例
     */
    private static $instance=null;

    protected $error;

    //默认配置
    protected $config = [
        'auth_on' => 1, // 权限开关
        'auth_type' => 1, // 认证方式，1为实时认证；2为登录认证。
        'auth_group' => 'auth_group', // 用户组数据表名
        'auth_group_access' => 'auth_group_access', // 用户-用户组关系表
        'auth_rule' => 'auth_rule', // 权限规则表
        'auth_user' => 'admin', // 用户信息表
        'menu' =>'menu'
    ];

    /**
     * 类架构函数
     * AuthManager constructor.
     * @param $options
     */
    private function __construct($options)
    {
        //可设置配置项 auth, 此配置项为数组。
        if ($auth = Config::get('auth')) {
            $this->config = array_merge($this->config, $auth);
        }
    }

    /**
     * 设置错误信息
     * @param $message
     */
    public function setError($message){
        $this->error=$message;
    }

    /**
     * 获取错误信息
     * @return mixed
     */
    public function getError(){
        return $this->error;
    }

    /**
     * 初始化
     * @param array $options
     * @return object|AuthManager
     */
    public static function getInstance($options = array()){
        if(is_null(self::$instance)) {
            self::$instance=new self($options);
        }
        return self::$instance;
    }

    private function __clone(){
        throw new \Exception('禁止克隆');
    }

    /**
     * 获取权限菜单
     * @param $uid
     * @return array
     */
    public function getAuthMenu($uid){
        $auth = Auth::instance();
        $list = $auth->getAuthList($uid,1);
        $menu = Db::name('menu')->order('sort','desc')->select();

        //将菜单id作为数组key
        $keys = array_column($menu,'id');
        $menu = array_combine($keys,$menu);

        //返回有权限的菜单
        $menuList = []; $pids = [];
        foreach($menu as $key=>$value){
            $link = trim(strtolower($value['link']),DS);
            if(in_array($link,$list)){
                if($value['pid']!=0){
                    if(!in_array($value['pid'],$pids)){
                        $menuList[] = $menu[$value['pid']];
                        $pids[] = $value['pid'];
                    }
                }
                $menuList[] =  $value;
            }
        }

        $menus = Data::channelLevel($menuList);
        return $menus;
    }

    /**
     * 添加规则
     * @param $data
     * @return mixed
     */
    public function insertRule($data){
       return self::storeRule($data,'insert');
    }

    /**
     * 更新规则
     * @param $data
     * @return mixed
     */
    public function updateRule($data){
        return self::storeRule($data,'update');
    }

    /**
     * 规则增改
     * @param $data
     * @param string $scene
     * @return mixed
     */
    private function storeRule($data,$scene='insert'){
        $rule = [
            ['name','require|unique:'.$this->config['auth_rule'],'规则标识不能为空|规则名称要唯一'],
            ['title','require|chsAlphaNum','规则名称不能为空|规则名称只能汉字、字母和数字'],
            ['status','require|in:1,0','状态不能为空|非法状态数据'],
            ['mid','checkMid:1','请选择所属模块,所属模块为二级菜单']

        ];

        $validate = new Validate($rule);

        //扩展规则,菜单模块 是否在菜单表内
        $validate->extend('checkMid', function ($value, $rule) {
            $menu = Db::name($this->config['menu'])->where('pid','neq',0)->find($value);
            return  isset($menu)?true:false;
        });
        $result   = $validate->check($data);
        if($result){
            return Db::name($this->config['auth_rule'])->$scene($data);
        }else{
            $this->setError($validate->getError());
            return false;
        }
    }


    /**
     * 获取所有的权限节点
     * @param array $check 角色权限ids
     * @return array
     */
    public function getAllRule($check =array()){
        $menuList = Db::name('menu')->select();
        $menus = Data::channelLevel($menuList);
        foreach ($menus as &$menu){
            if (isset($menu['_data'])&&is_array($menu['_data'])){
                foreach ($menu['_data'] as $key => $rule){
                    $menu['_data'][$key]['_data'] = Db::name($this->config['auth_rule'])
                        ->where('status',1)
                        ->where('mid',$rule['id'])
                        ->select();

                    //当前二级菜单的所有下的 所有权限节点id
                    $child = $menu['_data'][$key]['_data'];
                    $child_id = array_column($child, 'id');


                    //角色表里面的rules 和 当前模块是否有交集
                    $result = array_intersect($check,$child_id);

                    if (count($result)>0){
                        $menu['_data'][$key]['check'] = 1;
                        $menu['check'] = 1;
                    }
                }
            }
        }
        return $menus;
    }


    /**
     * 添加角色
     * @param $data
     * @return mixed
     */
    public function insertGroup($data){
        return self::storeGroup($data,'insert');
    }

    /**
     * 更新角色
     * @param $data
     * @return mixed
     */
    public function updateGroup($data){
        return self::storeGroup($data,'update');
    }

    /**
     * 角色增改
     * @param $data
     * @param string $scene
     * @return mixed
     */
    private function storeGroup($data,$scene='insert'){
        $rule = [
            ['title','require|chsAlpha','角色名称不能为空|角色名称只能汉字字母'],
            ['status','require|in:1,0','状态不能为空|非法状态数据'],
            ['rules','checkRules:1','权限规则非法']
        ];
        $validate = new Validate($rule);

        //扩展规则,规则是否在数据库内
        $validate->extend('checkRules', function ($value, $rule) {
            if(!is_array($value)) return false;
            $count = Db::name($this->config['auth_rule'])->where('id','in',$value)->count();
            return  ($count==count($value))?true:false;
        });
        $result   = $validate->check($data);

        //将规则字段已字符串存数据库中
        $data['rules'] = implode(',',$data['rules']);
        if($result){
            return Db::name($this->config['auth_group'])->$scene($data);
        }else{
            $this->setError($validate->getError());
            return false;
        }
    }

    /**
     * 添加菜单
     * @param $data
     * @return mixed
     */
    public function insertMenu($data){
        return self::storeMenu($data,'insert');
    }

    /**
     * 更新菜单
     * @param $data
     * @return mixed
     */
    public function updateMenu($data){
        return self::storeMenu($data,'update');
    }

    /**
     *  菜单增改
     * @param $data
     * @param string $scene
     * @return mixed
     */
    protected function storeMenu($data,$scene='insert'){
        $rule = [
            ['pid','checkPid:1','请选择合法的父级菜单'],
            ['title','require|chs','菜单名称不能为空|菜单只能为中文'],
            ['sort','number','请输入整数排序'],
        ];
        $validate = new Validate($rule);

        //扩展规则,规则是否在数据库内
        $validate->extend('checkPid', function ($value, $rule) {
            if($value==0){
                return true;
            }
            $p_menu = Db::name($this->config['menu'])->find($value);
            return  $p_menu?true:false;
        });
        $result   = $validate->check($data);

        //将规则字段已字符串存数据库中
        if($result){
            return Db::name($this->config['menu'])->$scene($data);
        }else{
            $this->setError($validate->getError());
            return false;
        }
    }

}