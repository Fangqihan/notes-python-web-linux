
# Django框架解析

标签（空格分隔）： web框架

----------

## 前端相关
**展示内容**：浏览器接收后端返回的html文本(经过模板渲染)内容并在页面展示．
**与用户交互信息**：js将用户产生数据通过form表单形式或者ajax形式将数据传输到后台并接收返回信息，从而达到数据交互的作用．

----------

#### 请求的本质
**CS架构**：本质上django程序就是一个socket服务端，浏览器其实就是一个socket客户端．
django自带的wsgi模块处理浏览器的请求信息，用户只需要实现路由和视图函数、模板等代码部分．

----------


#### django请求的生命周期
指当用户在浏览器上输入url到用户看到网页的这个时间段内，Django程序内部所发生的事情，具体步骤如下:
1. 当用户在浏览器输入url时, 然后浏览器会生成请求头和请求体发送给服务器；
2. url经过wsgi---中间件---最后到达路由映射表，随后按顺序进行正则匹配，若匹配到,则进入对应的视图函数或者类(CBV)中；
3. 视图函数根据客户端的请求,取出数据并渲染到模板中,其中可能涉及ORM操作(增删改查)或从缓存取出数据, 最终以字符串的形式返回．

![](http://oyhijg3iv.bkt.clouddn.com/MTV.png)

----------

#### Form
表单提交，页面与web服务器交互数据最重要的方式．
基础信息详见：http://www.cnblogs.com/fqh202/p/8483862.html．

###### Django之Form组件
根据创建的form类，可以在页面自动生成form的input标签．

**创建form类**:
可以直接在app目录下新建**forms.py**文件．
在类中定义input标签．

```
from django.forms import Form
from django.forms import widgets
from django.forms import fields


class MyForm(Form):
    username = fields.CharField(
        # 可以对输入的数据进行初步筛选
        max_length=6,
        min_length=2,
        widget=widgets.TextInput(attrs={'id': 'i1', 'class': 'c1'})
    )

    # 多选一
    gender = fields.ChoiceField(
        choices=((1, '男'), (2, '女'),),
        initial=2,
        widget=widgets.RadioSelect
    )

    city = fields.CharField(
        initial=2,
        widget=widgets.Select(choices=((1, '上海'), (2, '北京'),)) # 下拉框
    )

    pwd = fields.CharField(
        min_length=6,
        widget=widgets.PasswordInput(attrs={'class': 'c1'}, render_value=True)
    )
```

**构建views.py逻辑**：
导入自定义的form类并实例化：`obj = MyForm()`．
若填充数据，`is_valid()`根据自定义的规则对表单数据进行验证，没有错误则通过`obj.clean()`以字典形式取出数据，若有错误，则错误信息以字典形式保存在`obj.errors`中．

```
from django.shortcuts import render, redirect
from .forms import MyForm


def login(request):
    if request.method == "GET":
        obj = MyForm()
        return render(request, 'login.html', {'form': obj})

    elif request.method == "POST":
        obj = MyForm(request.POST, request.FILES)
        errors={}
        if obj.is_valid():
            values = obj.clean()
            print(values)
        else:
            errors = obj.errors
            print(errors)
        return render(request, 'login.html', {'form': obj,'errors':errors})

    else:
        return redirect('http://www.baidu.com')
```

**在login.html动态生成input标签**：可以很方便的显示错误信息．

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>登录页面</title>
    <style>
        div{
            margin-bottom: 10px;
        }
        .error{
            font-size: 12px;
            color: red;
        }
    </style>
</head>
<body>


<form method="post" novalidate>
    {# １．常规制作input标签 #}
        {#    <label for="id_username">用户名</label><input type="text" id="id_username" name="username">#}
        {#    <label for="id_password">密码</label><input type="text" id="id_password" name="password">#}
        {#    <input type="submit">#}

    {# ２．模板语言结合自定义form动态生成input标签 #}
    <div>用户名{{ form.username }}<span class="error">{{ form.username.errors.0 }}</span></div>{# 可以直接显示错误信息 #}
    <div>性别{{ form.gender }}</div>
    <div>城市{{ form.city }}</div>
    <div>密码{{ form.pwd }}<span class="error">{{ form.pwd.errors.0 }}</span></div>
    <input type="submit">
    {% csrf_token %}
</form>


</body>
</html>
```


**常用控件**

```
// radio单选按钮，值为字符串==========================
gender = forms.ChoiceField(
    choices=((1, '男性'),(2, '女性'), (3, '中性'), ), initial=1, 
    widget=widgets.RadioSelect
)

gender = forms.CharField(
    initial=1, widget=widgets.RadioSelect(choices=((1, '男性'),(2, '女性'), (3, '中性'), ))
)


// 单select，值为字符串========================================
user = fields.CharField(
     initial=2,
     widget=widgets.Select(choices=((1,'上海'),(2,'北京'),))
)

user = fields.ChoiceField(
     choices=((1, '上海'), (2, '北京'),),
     initial=2,
     widget=widgets.Select
)
 

// 多选select，值为列表==========================================
user = fields.MultipleChoiceField(
     choices=((1,'上海'),(2,'北京'),),
     initial=[1,],
     widget=widgets.SelectMultiple
)
 

// 单checkbox
gender = forms.ChoiceField(initial=[2, ],choices=((1, '上海'), (2, '北京'),), widget=widgets.CheckboxInput)


// 多选checkbox,值为列表
user = fields.MultipleChoiceField(
     initial=[2, ],
     choices=((1, '上海'), (2, '北京'),),
     widget=widgets.CheckboxSelectMultiple
)
```
**自定义不能为空的错误信息**：

```
class RegisterForm(forms.Form):
    username = forms.CharField(min_length=2,error_messages={'required':'用户名不能为空'},
```

**正则自定义错误信息**：
１．存在多条验证时, 以列表或者元祖形式导入实例化的`RegexValidator`对象, django会按照顺序逐个验证,直到抛出错误信息;
２．传入两个参数: `匹配的正则表达式` 和 `错误信息`;
３．原理是若输入与正则不匹配,则抛出`ValidationError(错误信息)` 

```
from django.form import Form
from django.core.validators import RegexValidator

class UserForm(Form):
    username = forms.CharField(
        validators=[RegexValidator(r'^[0-9]+$', '请输入数字'), 
                    RegexValidator(r'^159[0-9]+$', '数字必须以159开头')],
        widget=widgets.TextInput(attrs={'class': 'form-control'}))
```

**自定义验证函数**

```
from django.core.exceptions import ValidationError
import re

def mobile_validate(value):
    mobile_re = re.compile(r'^(13[0-9]|15[012356789]|17[678]|18[0-9]|14[57])[0-9]{8}$')
    if not mobile_re.match(value):
        raise ValidationError('手机号码格式错误')


class UserForm(forms.Form):
    username = forms.CharField(validators=[mobile_validate, ], widget=widgets.TextInput(attrs={'class': 'form-control'}),)
```

**局部钩子**：重载内置的`clean_field()`方法，在form字段中定义的验证完成后，会执行`clean_field()`方法，此时通过`cleaned_data`取出值进行判断．

```python
from django import forms
from django.forms import widgets
from django.core.exceptions import ValidationError

class UserForm(Form):
    username = forms.CharField(widget=widgets.TextInput(attrs={'class': 'form-control'}),)
    
    def clean_username(self):
        value = self.cleaned_data['username']
        if value == 'alex':
            raise ValidationError('用户名已存在')
        return value
```

**全局钩子**：
重载系统的`clean()`方法（`clean(self)`是在`clean_field(self)`之后运行的）．
错误信息是保存在`obj.errors.__all__`中，可以通过自定义过滤器取出自定义的错误信息并在前端显示．


```
# forms.py
from django.forms import Form
from django.forms import widgets
from django.forms import fields
from django.core.validators import RegexValidator,ValidationError

class MyForm(Form):
   ....
    def clean(self):
        if self.cleaned_data.get('pwd1') != self.cleaned_data.get('pwd2'):
            raise ValidationError('密码不一致')
        else:
            return self.cleaned_data



// 自定义过滤器
from django import template
register = template.Library()

@register.filter
def get_error(error_dict):
    if error_dict.get('__all__'):
        return error_dict.get('__all__')[0]

// 前端显示自定义错误信息
 <div id="errors">
     {% if errors %}
        {{ errors|get_error }}
     {% endif %}
 </div>
```

###### 文件上传
**指定传输数据处理方式**: `enctype="multipart/form-data"`．
**取出文件**：文件的二进制格式保存在`request.FILES`中,在后台直接以字典方式取出．

**django配置media上传文件路径**：

```
// 1. setting.py配置
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media', "fileholder_name", ...) # 若存在多级目录,可以逐个写入文件夹名称即可

// 2. urls.py配置
from django.views.static import serve
from onlineLearningSys import settings
# 仅限于debug模式
urlpatterns += [
    url(r'^media/(?P<path>.*)$', serve, {
        'document_root': settings.MEDIA_ROOT,
    }),
]


// 3. models.py
# 图片是以路径字符串的形式存储在数据库的;
image = models.ImageField(upload_to="user/%Y/%m", verbose_name='图片', max_length=100, default='static/images/xgt.jpg')


// 4. html文件，类似于imageField存储的格式是: organization/2018/03/1499239092.png, 必须在加上media前缀
 <a href="org-detail-homepage.html">
    <img width="200" height="120" class="scrollLoading" data-url="/media/{{ org.org_image }}"/>
</a>
```

**后台取出文件并利用model方式保存**：

```
# views.py 保存用户图片信息
def ***()
    img = request.FILES.get('img')
    user = UerProfile.objects.create_user(
    	username=username,
    	password=password,
    	img= img,
    )
    user.save()
```

**手动保存文件**：很少用到！

```
file_obj = request.FILES.get('upload_file')
f1 = open(file_obj.name, "wb")

# 方法1
for i in file_obj:
    f1.write(i)
    
# 方法2
for i in file_obj.chunks():
    f1.write(i)
```


#### 补充
在form表单中，只有`<input type="button" id="btn" vaule='提交'>`触发的事件不会自动提交表单，`<button>`和`<input type="submit" id="btn">`都会自动提交表单，切记！

```
<form>
    <input type="text">
    <input type="button" id="btn" value='提交'>
</form>
```

----------

#### Ajax
通过js或者jquery在当前页面获取局部的数据，并将提交到后台．
**异步传输**：不会阻塞进程。
**局部刷新**：不会刷新整个页面。

###### Jquery实现Ajax发送
１．**常规方法**．
手动构建data，包括跨域请求csrf键值对．
只能传输简单的数据，不能传输文件，传输到后台的是文件的路径．

```
<script>
$('#submit_btn').click(function () {
	$.ajax({
	   url:'/login.html/',
	   type:"POST",
	   data: {'username':$('#username').val(), 
	   		'password': $("#password").val(),
			"csrfmiddlewaretoken":$('[name="csrfmiddlewaretoken"]').val()
	   },
	   success:function (data) {
			   alert(data)
		   }
		   
	})
});
</script>
```

２．**serialize方法**
直接将form标签序列化：`data: $('.post_form').serialize(),`
相对更简单，同样不能传递文件．

３．**formdata**
构建：`var form = new FormData()`．
有手动填充和自动填充两种方式．
**可以传输文件**．

```
// 手动填充form
$('#submit_btn').click(function () {
	 var form = new FormData();
	  form.append("username",$('#id_username').val());
	  form.append("password",$('#id_password').val());
	  form.append('csrfmiddlewaretoken', $('[name="csrfmiddlewaretoken"]').val());
	  
	  # 文件传输;
	  form.append('file',$('#upload_file')[0].files[0]);
	  
	 $.ajax({
		 url: '/login.html/',
		 type: 'post',
		 data: form,
		 processData: false,
		 contentType:false,
		 success: function (data) {
		 }
	 })
 });
			

// 自动填充
$('#submit_btn').click(function () {
    var form = new FormData($('#login_form')[0]); // 注意,必须传入DOM对象
    
    $.ajax({
     url: '/login.html/',
     type: 'post',
     data: form,
     processData: false,
     contentType:false,
     success: function (data) {
	    alert(data)
	 }
    
     })
});
```

###### JS实现Ajax发送


###### json简单介绍
javascript object notation缩写，基于javascript语言的轻量级数据交换格式．
**作用**：可靠性传递数据，不改变其类型，例如字典和列表．


|dict >> str >>| bytes>>|str >>> dict|
|:--:|:--:|:--:|
|json.dumps()|encode/decode|json.loads()|


**两种格式**：
1. `{key:value, ...}`：key是字符串,value可以为所有类型;
2. `[{k1:v1}, {k2:v2}, ...]`

**类型**：`string, number, boolean, array, object, null`

**易混淆概念**:
字符串：双引号或单引号包括的字符．
json字符串：符合json格式的字符串．
json对象：指符号json要求的js对象．

**在js中使用方法**：

```
# 创建json对象
var obj = {
	key: value, 
	k2: [], 
	k3: {k4:v4,...}
}

# 查询：obj.key

# 增加键值对或修改：obj.key = v2

# 删除：delete obj.key
```

#### 静态文件配置
1. 将所有静态文件放到一个static文件夹下, 主要是项目固有的js, css, img等不会更改的文件；
2. 每个应用都应该有自己的静态文件夹；
3. `settings.py`配置

    ```
    STATIC_URL='static/'
    STATICFILES_DIRS=[os.path.join(BASE_DIR, 'static')]
    ```
4. 前端引入：
    
    ```
    {% load staticfiles %}
    <link rel="stylesheet" href={% static 'css/bootstrap.css' %}">
    ```

#### Cookies & Session
由于WEB是无状态请求, 服务器不能直接识别用户的状态信息。

###### cookies简单使用
**获取Cookies**: `request.COOKIES.get("islogin",None)`。
**设置Cookies**：`obj.set_cookie("islogin",True)`。
**删除Cookies**: `obj.delete_cookie("cookie_key",path="/",domain=name)`

**实现cookies的简单用户认证登录**：

```
# views.py
def index(request):
    # 从本地的cookie查询,若找到对应的用户,则直接跳转主页面,否则重新登录
    is_login = request.COOKIES.get("bob", None)
    if is_login:
        return render(request, 'index.html')
    else:
        return redirect('/login/')

def my_login(request):
    if request.method=='POST':
        username = request.POST.get('username')
        pwd = request.POST.get('password')
        if username == 'bob' and pwd == 'abc123':
            obj = redirect("/index/")
            obj.set_cookie("bob", 'abc123', max_age=10)  # 设置cookie键值对,会保存在本地, 最大期限为10s;
            return obj
            
    return render(request, 'login.html')
```

###### cookies 和 session 结合使用
**COOKIE**：缓存在本地，每次请求携带信息`{SESSION_ID: 'ABC'}`；
**SESSION**：保存在服务器，即为SESSION表

```
SESSION_KEY = 'ABC'
SESSION_DATA = HASH({'DATA1', 'K2':'DATA2', ...})
```
**流程**：
１．客户端首次发送请求未携带cookie信息，django会给客户端返回cookie键值对`{session_id:'随机字符串'}`，作为客户端浏览器标识；
２．用户登录，设置session存储用户状态信息：

```
authenticate(username='', password='')  # 检验取出用户对象, 
login(request, user)  # 登录,生成session记录
```
３．当客户端再访问server则根据携带的cookie从session中取出对应的用户信息，也就是本地浏览器在session的有效期内再次访问服务器,无需登录,可以直接访问授权的页面。具体用户的状态信息怎么保存在session_data中,暂时不深究!

**session基本操作**：

```
# 1.设置session值
request.session["session_name"]="admin"
# 2.获取session值
session_name = request.session("session_name")
# 3.删除session值
del request.session["session_name"]  删除一组键值对
request.session.flush()   删除一条记录
# 4. 检测是否操作session值
`if "session_name"  is request.session:`
# 5. 取值
get(key, default=None)
fav_color = request.session.get('fav_color', 'red')

# 6.pop(key)
fav_color = request.session.pop('fav_color')
# 7、keys()
# 8、items()
10、flush() # 删除当前的会话数据并删除会话的Cookie，django.contrib.auth.logout() 函数中就会调用它。
# 用户session的随机字符串
request.session.session_key
# 将所有Session失效日期小于当前日期的数据删除
request.session.clear_expired()
# 检查 用户session的随机字符串 在数据库中是否
request.session.exists("session_key")
# 删除当前用户的所有Session数据
request.session.delete("session_key")
```

**session和cookies登录实例**

```
# 视图函数views.py

def index(request):
    # 直接取出之前存储的值
    if not request.session.get("is_login"):
        return redirect('/login/')
    else:
        return render(request, 'index.html')
    

def login_(request):
    if request.method == "GET":
        return render(request, 'login.html')
        
    username = request.POST.get('username')
    pwd = request.POST.get('password')
    if username == 'kate' and pwd == 'abc123':
        # 此时cookie信息django已经自动生成
        print(request.COOKIES)
        # {'csrftoken':'3KV1lSv2JqMVxTOtq1YNiUh8OjmhwACqoyCdSxwgCAcIK6NWWIozg1WtiMN4zfXL'}
        
        # 需要我们自己设置session存储的状态信息
        print(request.session)  # <django.contrib.sessions.backends.db.SessionStore object at 0x00000000042E77F0>
        request.session['is_login'] = True
        request.session['user'] = 'kate'
        return redirect('/index/')
```

----------

## 后端
**django相关命令**：
下载： `pip install django`
创建项目: `django-admin.py startproject pro_name`．
创建应用: `python manage.py startapp appname`．

#### 中间件Middlewares
位于wsgi和路由映射之间的一个模块，能够在全局上改变django的输入与输出，例如用户信息验证/日志记录等．
**中间件方法**: `process_request`，`process_response`，

###### 自定义中间件
１．在项目目录下创建文件夹`utils`, 内部创建`my_middleware.py`文件, 写入类`Md1`, 文件名称和类名称自定义;

```
from django.utils.deprecation import MiddlewareMixin

class Md1(MiddlewareMixin):
    def process_request(self, reqeust):
        print('md1_process_request')

    def process_response(self, requst, response):
        print('md1_process_response')
        return response  # 必须带返回值


class Md2(MiddlewareMixin):
    def process_request(self, request):
        print('md2_process_request')

    def process_response(self, request, response):
        print('md2_process_response')
        return response  # 必须带返回值
```
２．在配置文件中加入加上的中间件：

```
MIDDLEWARE = [
'utils.my_middleware.Md1',
'utils.my_middleware.Md2',
...
]
```
３．此时django所有的请求和相应都会依次经过`process_request()`和`process_response`函数．

```
# 结果
md1_process_request
md2_process_request
md2_process_response
md1_process_response
```

**process_request返回值**：
默认为`return None`，当需要过滤某些请求时，可以直接return．
当存在返回值，就不会继续往下执行，就地返回相应的返回值至浏览器．

```
class Md1(MiddlewareMixin):
    def process_request(self, request):
        print('md1_process_request')
        return HttpResponse('<h1>你好</h1>')
```

**process_response返回值**：
返回值就是Httpresponse返回的字符串，返回的字符串会经过中间件处理, 例如加上响应头数据，必须带返回值, 否则会出现系统错误．


**版本向后兼容**：为提高兼容性, 直接在自定义的Md上方写入以下源码,直接继承, 此时就无须导入(有时候版本不同, 文件位置会有变动)

```
class MiddlewareMixin(object):
    def __init__(self, get_response=None):
        self.get_response = get_response
        super(MiddlewareMixin, self).__init__()

    def __call__(self, request):
        response = None
        if hasattr(self, 'process_request'):
            response = self.process_request(request)
        if not response:
            response = self.get_response(request)
        if hasattr(self, 'process_response'):
            response = self.process_response(request, response)
        return response
```


###### 自定义中间件实现用户登录

```
# my_middleware.py
from django.utils.deprecation import MiddlewareMixin
from django.shortcuts import render

class Md1(MiddlewareMixin):

    def process_request(self, request):
        print('md1_process_request')
        # 若本次请求是login页面, 则当前中间件不做任何操作
        if request.path == '/login.html':
            return None
        # 若未取不到对应的信息,则跳转至登录页面,此处直接render
        if not request.session.get('user_info'):
            return render(request, 'login.html')

    def process_response(self, request, response):
        print('md1_process_response')
        return response  # 必须带返回值
```

在配置文件中,自定制中间件尽可能放在尾部，因为必须经过django自带的中间件处理再进行自定义判断．
注意重定向的问题，若取不到session信息就直接redirect登录url的话,就会出现无限从定向问题,因为下一次回到这里还是没有session信息,所以直接render页面,避免此问题;


###### process_view方法
到达路由映射匹配视图函数时又再一次有上到下运行每个中间件的`process_view`方法．
`process_view`函数默认`return None`，若带返回值的话，那么后面中间件的`process_view`都不会执行, 直接跳转到尾部执行`process_response`, 返回值为`process_view`的返回值．


###### process_exception捕捉异常
捕捉请求url相关的视图函数中的异常，若没有发生异常,此函数是不会运行的．
中间件会按照由下至上的顺序执行此方法，若存在返回值,则直接将返回值交给`process_response`返回，但是上面的中间件仍然会执行完此方法!

![中间件运行流程](http://oyhijg3iv.bkt.clouddn.com/%E4%B8%AD%E9%97%B4%E4%BB%B6.png)

----------

#### 路由映射urls
url路径与视图一一对应的关系．
传过来的请求路径与urls中的正则从上至下匹配,若匹配到则直接调动对应的视图函数．

###### 命名
**name**：对url命名，当url有变动时候，无须修改其他地方的引用！

```
# urls.py
url(r'^test/(?P<i>\d{1,4})', app1_view.test, name='test'),

# index.html 在页面直接通过name属性定位url，且可以传递一个参数
<a href="{% url 'test' 111 %}">点我</a>
```

**namespace**：在include中使用，针对多层级urls.py．
初步匹配后进入include中的app的urls进一步匹配;
在利用模板语言标签{% url 'namespace: name' %}可以调用，保证url的唯一性．

```
# 项目主目录
from django.conf.urls import url,include
urlpatterns = [
    url(r'^user/', include('app01.urls',namespace='users')),
]

# app01.urls
from django.conf.urls import url,include
urlpatterns = [
    url(r'^register/(\d+)/', app1_view.register,name='register'),
]

# index.html 点击a标签会直接定位到对应的url
<a href="{% url 'users:register' %} ">点我2</a>
```

###### 请求路径相关
**`<a href='/login/'>`**：以斜杠开始的路径, 直接当前域名后追加此路径；

**`<a href='login/'>`**：没有反斜杠,在当前url后追加此路径；

**`<a href='?city="wuhan"&province="hubei"'></a>`**：直接在后台通过request.GET中以字典方式取出数据，`{city:"wuhan;province:"hubei"}`，可以作为分组判断条件；

**`<a href='/test/1/'></a>`**：
此处的数字 1 可以在 后台作为参数接收．
无名分组：`url(r'^test/(\d{0,4})/', views.f1),`，函数接收参 `f1(request, id)`；
命名分组：若路径中存在多个参数，那么可以采用命名分组：`url(r'^test/(?P<id>\d{4})/(?P<month>\d{2})', views.func),`．

**`<form action=''>`和ajax中的`url=''`同理**．

----------

#### 视图VIEW
**两种请求方式**：`get`，`post`．

###### 三种方法
**`render(request, 'index.html', {k:v,..})`**：从数据库中取出数据渲染到模板，再返回给浏览器展示，或者直接返回模板内容到浏览器．

**`HttpResponse(str)`**：返回固定字符串，若为标签文本，页面亦可以识别.

**`redirect('/login/')`**：重新到路由配置下匹配url．

函数方式：url对应的是视图函数

###### CBV模型
url对应一个视图类．此类调用父类的`dispatch()`方法，会根据http请求头里的方法是`get`还是`post`方法来执行相应的函数。在触发视图类的时候可以在dispatch函数内部实现一些逻辑判断．

```
from django.views import View
from django.shortcuts import render, redirect,HttpResponse

class LoginView(View):
    def dispatch(self, request, *args, **kwargs):
        '''可以在内部做出逻辑判断'''
        if request.POST.get('username')=='alex':
            return HttpResponse('用户名已注册')
        ret = super(LoginView, self).dispatch(request, *args, **kwargs)
        return ret

    def get(self, request):
        obj = MyForm()
        return render(request, 'login.html', {'form': obj})

    def post(self, request):
        obj = MyForm(request.POST, request.FILES)
        errors = {}
        if obj.is_valid():
            values = obj.clean()
            print(values)
        else:
            errors = obj.errors
            print(errors)
        return render(request, 'login.html', {'form': obj, 'errors': errors})
```

**弊端**：每个视图类内部都需要定义dispatch函数，造成重复代码．

----------

#### 模板Template
通过模板语法渲染从数据库中取出的数据．
###### 变量
一般是以字典形式放在上下文中：`{'book', book_obj}`，通过视图逻辑render到模板中．
**查询语法**:
`{{ iterable.0 }}`：若后端传入的集合为列表或者元祖，那么可以根据索引取出元素；
`{{ dict.key}}`：若为字典；
`{{ book.index.author}}`：若为类对象．

	
###### 标签
**语法**：`{%  %}`

**循环**：在前端遍历对象集合并取出属性值

```
{% for person in person_list %}
    <p>{{person.name}}</p>
{% empty %)  // 判断是否为空，内置标签判断
    <p>没有符合的结果</p>
{%  endfor %}
```	

**分支判断**:

```
{% if i > 100 %}
    <p>100</p>
{% else %}
    <p>{{i}}</p>
{% endif %}
```

**`{% with %}`**：使用一个简单地名字缓存一个复杂的变量，当你需要使用一个“昂贵的”方法（比如访问数据库）很多次的时候是非常有用的

```
{% with total=business.employees.count %}
    {{ total }} employee{{ total|pluralize }}
{% endwith %}
```

**当前循环计数**：`{{forloop.counter}}`；


###### 内置过滤器
**取值**：
`{{html_str|first}}`：返回value的第一个元素, 对有序集合和列表都适用．
`{{html_str|last}}`：同first相反．
`{{ value|get_digit:"2" }}`：value为数字，返回从右往左数第2个数字．

**修改**：
`{{html_str|slice:10}}`：返回前10个元素．
`{{str|truncatechars:'int'}}`：截断字符,超过部分用`...`取代．

**增**：
`{{value|add: arg}}`:将arg添加至value中。若value为4，argu为2，则输出6；若value为[1,2,3], argu为[4,5,6]，则结果为[1,2,3,4,5,6]．

**删**：
`{{value|cut: arg}}`：删除value中所有的argu。若value为'hello  world'  argu为 ''，则输出 helloworld．

**功能**：
`length`：返回value的长度．
`capfirst`: 首字母大写．
`lower`：小写．
`make_list`：将value转换为list，例如value为‘123’，则输出[1,2,3]
`random`  从value中随 机挑选一个元素并返回
`{{html_str|safe}}`：保证页面的安全性，默认将变量内容转换成纯文本显示．加上safe，确定你的数据是安全的才能被当成是标签
`{{ datetime_instance|date:"Y-m-j G:i" }}`：显示结果`2016-8-8 8:08`．



###### 自定义过滤器
**配置**：
１．在`settings.py`中的`INSTALLED_APPS`配置当前app，不然django无法找到自定义的`simple_tag`；
２．在对应的app应用目录下创建`templatetags`模块(模块名只能是templatetags)；
３．在templatetags里面创建任意`my_tags.py`文件；


**无参数**：

```
# 1. 生成注册类
from django import template
register = template.Library()

# 2. 定义过滤器并注册
@register.filter
def square(value):
    try:
    	return int(value)**2
    except:
    	return '输入必须为数字'	
```	

**有参数**：`{{ html_str|add:"11" }}`，只能传递一个参数．

```	
@register.filter
def add(value, arg):
    try:
    	return int(value)+int(arg)*10
    except:
    	return '输入必须为数字'
```

在模板中使用`{% load 'filename' %}`标签装载自定义标签或者装饰器．


###### 自定义标签
在后端可以先在后台自定义标签中将要展现的内容制作成标签字符串，在前端直接调用标签语言就可以呈现内容．

```
from django import template
from django.utils.safestring import mark_safe

register = template.Library()

@register.simple_tag
def get_html(s1, s2):
	html = mark_safe('<h1>标题1{0}</h1><h2>标题2{1}</h2>'.format(s1, s2))
	return html

# 在前端直接引用
{% load my_tag%}

{% tag_name arg1 arg2 %}
```

###### 模板继承
`{% extends 'base.html' %}`必须放在首行．

覆盖父模板盒子中的内容：`{% block name %} 重新定制的代码 {% endblock %}`，盒子越多越好，灵活性更好．

`{% include "test.html" %}`：直接在当前模板引入文件`test.html`的内容;
取到父模板盒子的内容，然后再对其追加内容：`{{ block.super }}`．

#### Model
以类的方式创建和保存数据．

**具体步骤**
１．在终端创建数据库`db_pro`；
２．在setting中配置连接数据：

```
# 若使用mysql
DATABASES = {
	'default': {
		'ENGINE': 'django.db.backends.mysql',   # 数据库引擎
		'NAME': 'db_pro',       # 你要存储数据的库名，事先要创建之
		'USER': 'root',         # 数据库用户名
		'PASSWORD': '...',      # 密码
		'HOST': 'localhost',    # 主机
		'PORT': '3306',         # 数据库使用的端口
	}
}	

```

３．在app的init文件中配置，本身就是通过pymysql对数据库进行操作:

```
# 先安装pymysql模块，pip install pymysql
import pymysql
pymysql.install_as_MySQLdb()
```
４． 在model中创建模型
５．数据迁移，若需要使用后台添加数据则需要创建超级用户：`python manage.py createsuperuser`

```
python manage.py makemigrations
python manage.py migrate
```
６．生成表
django自带的表：session表，auth权限表，迁移记录表
model用户新建的表：`app_class_name`


**在model中自定义错误信息**：

###### 创建表结构
自定义model类．
**常用model字段**：

```
# 示例
class Course(models.Model):
    name = models.CharField(max_length=50, verbose_name='课程名')
    detail = models.TextField(verbose_name='课程详情')
    degree = models.CharField(choices=(('CJ', '初级'), ('ZJ', '中级'), ('GJ', '高级')), max_length=10)
    learn_times = models.IntegerField(default=0, verbose_name='学习时长(分钟)')
    org = models.ForeignKey(CourseOrg, verbose_name="所属课程机构")
    image = models.ImageField(upload_to="course/%Y/%m",verbose_name='课程图片', max_length=100)
    add_time = models.DateTimeField(default=datetime.now,verbose_name='课程添加时间')
    recommend = models.BooleanField(default=False,verbose_name='是否推荐',max_length=2)
    
FileField
EmailField
```
model中的字段类型自带检测功能，不满足条件时候会报错．在admin添加记录时候自动截断，例如限制最大长度，那么只取最大长度的字符串．
**表关系同mysql数据库**．


###### admin相关
可以在admin后台对表进行记录操作．
**注册model**：必须在app下的`admin.py`注册model的类后才能在后台显示.

```
from django.contrib import admin
from app.models import Book

admin.site.register(Book)
```

**修改显示表名**：

```
def __str__:	
	return self.name
```

**修改显示的字段名**：`verbose_name = ''`
	
**定义显示的字段**:

```
# admin.py
from django.contrib import admin
from blog.models import Blog
  
#Blog模型的管理器
class BlogAdmin(admin.ModelAdmin):
	list_display=('id', 'caption', 'author', 'publish_time')
	 
#在admin中注册绑定
admin.site.register(Blog, BlogAdmin)
```

**修改表名**:

```
	class Meta:
		db_table = 'new_name'
```		


###### 表记录操作
**增加记录**：实例化并赋值, 随后save();

```
# 方法1
book = Book(**kwargs)
book.save()

# 方法2
Book.create(**kwargs)
```		
**删记录**：`Book.objects.filter(title='').delete()`
**改记录**：

```
# 方法1:
Book.objects.filter(title='t1').update(title='t2')

# 方法2:
b = Book.objects.get('')
b.title = ''
b.save()
```

###### 单表查询
ORM操作主要是查询操作．

```
# 只针对int类型字段大小比较
models.Tb1.objects.filter(id__gt=1)              # 获取id大于1的值
models.Tb1.objects.filter(id__gte=1)             # 获取id大于等于1的值
models.Tb1.objects.filter(id__lt=10)             # 获取id小于10的值
models.Tb1.objects.filter(id__lte=10)            # 获取id小于10的值
models.Tb1.objects.filter(id__lt=10, id__gt=1)   # 获取id大于1 且 小于10的值

# in范围比较
models.Tb1.objects.filter(id__in=[11, 22, 33])   # 获取id等于11、22、33的数据
# not in
models.Tb1.objects.exclude(id__in=[11, 22, 33])  # not in
# range
models.Tb1.objects.filter(id__range=[1, 2])   # 范围bettwen and

# isnull
Entry.objects.filter(pub_date__isnull=True)

# 其他类似
startswith，istartswith, endswith, iendswith,
# contains包含
models.Tb1.objects.filter(name__contains="ven")
models.Tb1.objects.filter(name__icontains="ven") # icontains大小写不敏感
models.Tb1.objects.exclude(name__icontains="ven")
# regex正则匹配，iregex 不区分大小写
Entry.objects.get(title__regex=r'^(An?|The) +')
Entry.objects.get(title__iregex=r'^(an?|the) +')

# 升序
orderby('id')  
orderby('-id')  # 降序列
# 切片
models.Tb1.objects.all()[10:20]

.get()  # 有就返回首个,没有报错;
.only('id', 'title')    # 只取某些字段
```

###### 基于对象的查询

```
# 查询linux这本书的出版社的地址
book_obj = Book.objects.filter(title="linux").first()
addr = book_obj.publisher.address

# 查询这本书的所有作者
book_obj = Book.objects.filter(title="蒋勋说唐诗").first()
authors = book_obj.author.all()
```

###### 基于双下划线的跨表查询
通过表之间的外键产生联系才能连表查询。以下练习是基于书｜出版社｜作者三张表。主要分为正向和反向查询两种思维方式。
**分组annotate**：

```
ret = Book.objects.values('category_title').annotate(count=Count('id')
	avg_price = Avg('price')
)
结果 <QuerySet [{'count': 3, 'avg_price': 59.0, 'category__title': '历史'}, 
{'count': 2, 'avg_price': 55.0, 'category__title': '小说'}]>
```

**聚合函数aggregate**：

```
ret = Book.objects.aggregate(count=Count('id'), avg_price= Avg('price'))
结果 {'avg_price': 57.4, 'count': 5}
```

**`values('id', 'title')`**：每一行记录为一个字典，整体是list列表，
例如`[{'id'：1,'title':'asa'},...]`.

**`value_list('id','title')`**：每一行记录的为一个元祖,整体是list列表．
例如`[(1,'asas'),...]`．

练习１．查询linux这本书的出版社地址：

```
# 方法1. 先定位book表,  在values中联表查询
addr = Book.objects.filter(title="linux").values("publisher__name","publisher__address")
print(addr)

# 方法2. 先定位出版社, 在filter中联表查询
result = Publisher.objects.filter(book__title="linux").values("address", "name")
print(result)
```
联系２．查询"蒋勋说唐诗"这本书的所有作者的名字：

```
# 方法1: 正向查询,先找出书,随后连表查询关联的作者
authors = Book.objects.filter(title="蒋勋说唐诗").values("author__name")
print(authors)

# 方法2:先找出作者,在过滤中连表筛选
res = Author.objects.filter(book__title="蒋勋说唐诗").values("name")
print(res)
```
练习３．查询价格大于40的书籍的作者姓名

```
# 方法1:正向查询, 从书入手
res = Book.objects.filter(price__gt=40).values("author__name").distinct()

# 反向查询,从作者入手
res = Author.objects.filter(book__price__gt=40).values("book__title").distinct()
```

###### 聚合查询aggregate()
作用对象是整个`query_set`集合或者一个列表，返回一个字典: `{要计算的字段名: 函数返回的结果, ..}`，此方法需要配合计算函数使用: `Avg`, `Sum`, `Count`, `Max`, `Min`．
**练习1：查询所有图书的平均价格**

```
from django.db.models import Avg, Sum,Count,Max,Min
ret = models.Book.objects.all().aggregate(Avg('price'), Sum('price'))

mysql> select avg(price), sum(price) from booksys_book;
结果: {'price__avg': 70.63636363636364, 'price__sum': 777}
```

**练习2: 查询"人民出版社"出版的最贵的书**

```
res = Publisher.objects.get(name="人民出版社").book_set.values("price",'title').aggregate(Max("price"))

结果: {'price__max': 111}

// 多个字段一样查询
models.Publisher.objects.get(id=1).books.values('title', 'price').aggregate(Max('price'), Sum('price'))
{'price__max': 111, 'price__sum': 400}
```

###### 分组查询annotate()
作用对象是每个分组, 可以通过`values()`指定分组的字段; 
2. 返回的是`query_set`集合的键值对, 包含分组字段和查询字段以及对应的值;
3. 此方法需要配合计算函数使用: `Avg`, `Sum`, `Count`, `Max`, `Min`

练习1: 查询每一个作者出版过书的最高价格

```
# values相当于对书籍分类进行分组，随后再利用annotate对每个分组用聚合函数
res = Book.objects.values("type").annotate(Max("price")))

<QuerySet [{'type': '1', 'price__max': 66}, {'type': '10', 'price__max': 23}, {'type': '2', 'price__max': 33}, {'type': '3', 'price__max': 200}]>
```
练习2: 每个出版社出版过的最高价格的书

```
models.Book.objects.values('publisher').distinct().annotate(Max('price'))

<QuerySet [{'publisher': 1, 'price__max': 111}, {'publisher': 2, 'price__max': 200}]>
```

###### F查询
可以在查询中引用字段，来比较同一个 model 实例中两个不同字段的值。

```
// 练习1: 查看评论数大于阅读数的书
models.Book.objects.filter(comment_num=F('read_num'))

// 练习2: 给每本书涨价20元
mysql> update booksys_book set price+=10;
# 貌似每次最大递增有限制
Book.objects.all().update(price=F("price")+20)
```

###### Q查询
支持的逻辑运算符: 与`&`, 或`|`, 非`~` 

```
# 查询以"蒋"开头且价格大于50的书
book = Book.objects.filter(title__startswith="蒋", price__gt=50).values('title', "price")

# 查询以"钢"开头或价格大于100的所有书
models.Book.objects.filter(Q(title__startswith='钢')|Q(price__gt=100)).all()
```

###### 查看数据库的sql语句（加在settings.py）

```
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console':{
            'level':'DEBUG',
            'class':'logging.StreamHandler',
        },
    },
    'loggers': {
        'django.db.backends': {
            'handlers': ['console'],
            'propagate': True,
            'level':'DEBUG',
        },
    }
}
```

#### Django内置功能

###### 信号
**内置信号**：

```
pre_init            # Django中的model对象执行其构造方法前,自动触发
post_init           # Django中的model对象执行其构造方法后,自动触发
pre_save            # Django中的model对象保存前,自动触发
post_save           # Django中的model对象保存后,自动触发
pre_delete          # Django中的model对象删除前,自动触发
post_delete         # Django中的model对象删除后,自动触发
m2m_changed         #Django中的model对象使用m2m字段操作数据库的第三张表(add,remove,clear,update),自动触发
class_prepared  　　# 程序启动时,检测到已注册的model类,对于每一个类,自动触发
request_started     # 请求到来前,自动触发
request_finished    # 请求结束后,自动触发
got_request_exception           # 请求异常时,自动触发
setting_changed     # 配置文件改变时,自动触发
template_rendered   # 模板执行渲染操作时,自动触发
connection_created  # 创建数据库连接时,自动触发
```

**内置信号使用步骤**：
１．自定义功能函数，并且将其绑定到内置信号上：

```
// 项目启动目录init.py

#导入需要引用的内置信号
from django.db.models.signals import pre_save, post_save 

def pre_save_func(sender, **kwargs):
    print('pre_save_fun')
    print('pre_save_msg:', sender, kwargs)

def post_save_func(sender, **kwargs):
    print('post_save_func')
    print('post_save_msg:', sender,kwargs)

pre_save.connect(pre_save_func)  # 绑定功能函数到信号
post_save.connect(post_save_func)


# 打印结果
sender:  <class 'app01.models.UserInfo'>  # model类
参数(键值对): {'signal': <django.db.models.signals.ModelSignal object at 0x0000000002E5F0B8>, 'instance': <UserInfo: UserInfo object>, '
created': True, 'update_fields': None, 'raw': False, 'using': 'default'
}

```
**自定义信号**
１．在项目根目录下创建`signal_test.py`文件, 定义信号
    
```
import django.dispatch
action=django.dispatch.Signal(providing_args=["aaa","bbb"])
```
２．还是在项目应用的`init`文件中完成功能函数和绑定信号

```
from signal_test import action

def pre_save_func(sender, **kwargs):
    print("pre_save_func")
    print("pre_save_msg:", sender, kwargs)

action.connect(pre_save_func)
```
３．在视图函数中触发信号

```
def add_user(request):
    UserInfo.objects.create(name='alex', age=12)
    action.send(sender='python', aaa=111, bbb=222)
    return HttpResponse('添加成功')
```
４．结果展示

```
sender:python 
参数: {'signal': <django.dispatch.dispatcher.Signal object at 0x0000000003CCC5F8>, 'aaa': 111, 'bbb': 222}

```

**信号和中间件的区别**：信号比中间件散布的范围更广。在后台的许多动作事件都可以触发内置的信号，从而执行与之绑定的函数，也可以自定义信号扩展其功能；而中间件常用的就只有四个函数，且仅在接受请求和返回请求的过程中起作用。

###### 缓存
由于Django是动态网站，所有每次请求可能进行数据库相关操作，当程序访问量大时，耗时必然会更加明显，最简单解决方式是使用缓存。缓存将一个某个views的返回值保存至内存或者memcache中，在有效时间内不再去执行view中的操作，而是直接从内存或者Redis中之前缓存的内容拿到并返回。

![缓存过程](http://oyhijg3iv.bkt.clouddn.com/%E7%BC%93%E5%AD%98.png)

**按照存储位置的六种缓存方式**：
１．内存中缓存: 内容以字符串形式存储在内存中, 但是位置无法确定!

```
# setting.py
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-snowflake',
        'TIMEOUT': 300,  # 缓存超时时间（默认300，None表示永不过期，0表示立即过期）
        'OPTIONS': {
            'MAX_ENTRIES': 300,  # 最大缓存个数（默认300）
            'CULL_FREQUENCY': 3,  # 缓存到达最大个数之后，剔除缓存个数的比例，即：1/CULL_FREQUENCY（默认3）
        },

    }
}
```
２，文件中缓存: 保存至指定的文件

```
CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
            'LOCATION': '/var/tmp/django_cache', # 需要指定文件夹路径
        }
    }
# 注：其他配置同开发调试版本
```

３，数据库中缓存

```
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.db.DatabaseCache',
        'LOCATION': 'my_cache_table', # 数据库表
    }
}

# 注：执行创建表命令 python manage.py createcachetable
```

４，Memcache缓存（python-memcached模块）

```
CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.memcached.MemcachedCache',
            'LOCATION': '127.0.0.1:11211',  # 类似于连接远程缓存服务器
        }
    }
	
	 CACHES = {
	        'default': {
	            'BACKEND': 'django.core.cache.backends.memcached.MemcachedCache',
	            'LOCATION': [
	                # # 支持简单的分布式,将数据分别存储在多个内存中, 防止其中一个缓存清空
	                '172.19.26.240:11211',  
	                '172.19.26.242:11211',
	            ]
	        }
	    }
	
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.memcached.MemcachedCache',
            'LOCATION': 'unix:/tmp/memcached.sock',
        }
}   
```
    
**按照缓存的使用范围分类**
１，全栈缓存
url经过一系列的认证等操作，如果请求的内容在缓存中存在，则使用`FetchFromCacheMiddleware` 获取内容并返回给用户，当返回给用户之前，判断缓存中是否已经存在，如果不存在则`UpdateCacheMiddleware`会将缓存保存至缓存，从而实现全站缓存。

```
# setting.py配置
MIDDLEWARE = [
'django.middleware.cache.UpdateCacheMiddleware',
# 中间放其他中间件
'django.middleware.cache.FetchFromCacheMiddleware',
]

CACHE_MIDDLEWARE_SECONDS = 5  # 每隔5s更新数据


# views.py
# 可以模拟每次访问, 看是否user信息是否更新, 结果是每5s一次更新一条数据, 说明前4s的所有请求都没有到views视图函数中,直接从缓存中拿取数据
def add_user(request):
    UserInfo.objects.create(name='alex', age=12)
    user_list = UserInfo.objects.all()  # 在有效时间内有限从缓存中取数据，所以不会及时更新
    return render(request, 'index.html', {
        'user_list': user_list
    })

```

２，单独视图实现缓存，例如某些静态页面可以使用此方法

```
＃　方式一：
from django.views.decorators.cache import cache_page

# 参数为更新的时间(s)
@cache_page(60 * 15)
def my_view(request):
    ...

＃　方式二：
from django.views.decorators.cache import cache_page

urlpatterns = [
    url(r'^foo/([0-9]{1,2})/$', cache_page(60 * 15)(my_view)),
]
```

３，页面的局部更新，例如购物网站中商品信息和价格都需要要实时更新，但是剩余数量一般都需要实时更新。
利用模板局部缓存时候，请求会进行数据库相关操作，唯一不同的是,在更新时间内不会将数据渲染到模板中而已。

```
<!DOCTYPE html>
# 在模板中导入内置的中间件
{% load cache %}

<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>主页面</title>
</head>
<body>
    <h1>主界面</h1>

    {% cache 3 '局部刷新' %}
        {% for user in user_list %}
            {{ user.name }}
        {% endfor %}
    {% endcache %}

</body>
</html>
```

