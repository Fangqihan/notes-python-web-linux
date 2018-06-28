# Django功能扩展

标签（空格分隔）： web框架

----------

## 用户注册

#### 用户信息表
扩展自带的user表字段，配置如下：
**app/models.py**

```
from django.db import models
from django.contrib.auth.models import AbstractUser

class UserInfo(AbstractUser):
    """扩展用户信息表"""
    nickname = models.CharField(max_length=50, verbose_name='昵称', null=True, blank=True)
    telephone = models.CharField(max_length=11, blank=True, null=True, unique=True, verbose_name='手机号码')
    avatar = models.FileField(verbose_name='头像',upload_to='user/%Y/%m',default='static/img/default.jpg')

    def __str__(self):
        return self.username

    class Meta:
        verbose_name = '用户信息'
        verbose_name_plural = verbose_name
        db_table='用户信息'
```
**settings.py**：`AUTH_USER_MODEL = 'app01.UserInfo'`

----------

#### auth模块

```
from django.contrib import auth, login, logout, authenticate
from django.contrib.auth.decorators import login_required
```
**查询用户**：根据用户名和密码信息匹配用户，`authenticate(username='alex',password='abc123')，匹配到则返回用户对象。

**用户登录**：`login(request,user)`，在session表中创建或更新session_data信息。

**注销用户**：`logout(request)`，删除session表中的记录。

**明文密码加密保存**：

```
from django.contrib.auth.hashers import make_password
user = UserProfile.objects.filter(...)
user.password = make_password(pwd)  # 转换成密码保存
user.save()
```
**重置密码**：

```
# 先检查输入密码是否与数据库中的密码一致，返回布尔值；
request.user.check_password(old_pwd)
# 设置新密码
request.user.set_password(new_pwd)
# 保存密码
request.user.save()
```

----------

#### django-form实现注册
**static常用
静态文件下载**：https://pan.baidu.com/s/1enDck7W-NSW0St2h4XiHBA
**urls.py**：

```
from django.conf.urls import url,include
from django.contrib import admin
from app01 import views as app1_view

urlpatterns = [
    url(r'^register/', app1_view.register),  
    url(r'^captcha/', app1_view.get_valid_img), # 验证码路径
]

from django.views.static import serve
from pro_2 import settings
# 仅限于debug模式
urlpatterns += [
    url(r'^media/(?P<path>.*)$', serve, {
        'document_root': settings.MEDIA_ROOT,
    }),
]
```

**app/forms.py**：自定制django的RegisterForm，自定制error_messages以及使用局部钩子和全局钩子函数对信息进行多重验证验证。

```
from django import forms
from django.forms import widgets
from django.forms import ValidationError


class RegisterForm(forms.Form):
    # 可以在error_messages中自定义错误信息
    username = forms.CharField(min_length=2, error_messages={'required':'用户名不能为空','min_length':'至少为4位'},
                               widget=widgets.TextInput(attrs={"placeholder": "用户名"}))
    password1 = forms.CharField(min_length=4, error_messages={'required':'密码不能为空','min_length':'至少为4位'},
                                widget=widgets.PasswordInput(attrs={"placeholder": "密码1"}))
    password2 = forms.CharField(min_length=4, error_messages={'required':'密码不能为空','min_length':'至少为4位'},
                                widget=widgets.PasswordInput(attrs={"placeholder": "密码2"}))
    email = forms.EmailField(max_length=50, error_messages={'required':'邮箱不能为空格','min_length':'至少为4位'},
                             widget=widgets.EmailInput(attrs={"placeholder": "邮箱"}))
    valid_code = forms.CharField(min_length=6, error_messages={'required':'验证码不能为空','min_length':'至少为6位',
                                                               },
                                 max_length=6, widget=widgets.TextInput(attrs={"placeholder": "验证码"}))

    def __init__(self, request, *args, **kwargs):
        super(RegisterForm, self).__init__(*args, **kwargs)
        self.request = request

    def clean_password1(self):
        '''自定义密码检测'''
        if self.cleaned_data['password1'].isalpha() or self.cleaned_data['password1'].isdigit():
            raise ValidationError('密码不能全为数字或者字母')
        else:
            return self.cleaned_data['password1']

    def clean_password2(self):
        '''自定义密码检测'''
        if len(self.cleaned_data['password2']) < 6:
            raise ValidationError('密码长度小于六位')
        elif self.cleaned_data['password2'].isalpha() or self.cleaned_data['password2'].isdigit():
            raise ValidationError('密码不能全为数字或者字母')
        else:
            return self.cleaned_data['password2']

    def clean_valid_code(self):
        '''检测验证码是否匹配'''
        if self.cleaned_data["valid_code"].upper() == self.request.session["valid_code"].upper():
            return self.cleaned_data["valid_code"]
        else:
            print('验证码错误')
            raise ValidationError("验证码错误！")

    def clean(self):
        '''密码一致性检测'''
        if self.cleaned_data.get('password1','') == self.cleaned_data.get('password2',''):
            return self.cleaned_data
        else:
            raise ValidationError("密码不一致")
```

**register.html**：注意提前导入Jquery模块，可以实现django-form上传用户注册信息，包括动态验证码和上传图片动态显示功能。

```
<!DOCTYPE html>
{% load static %}
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>注册页面</title>
    <style>
        div{
            margin-bottom: 10px;
        }
        .reg_error{
            color: red;
            font-size: 10px;
        }
        .valid{
            {# 行内文字与图片对齐#}
            vertical-align: middle;
        }

    </style>

    <script src="{% static 'js/jquery-3.3.1.js' %}"></script>
</head>
<body>
<form method="post" enctype="multipart/form-data" novalidate>
    {% csrf_token %}

      <div >
        <label for="username">用户名</label>
          {{ register_form.username }}<span class="reg_error" id="username_err">{{ errors.username.0 }}</span>
      </div>

      <div >
        <label for="password1">密码</label>
          {{ register_form.password1 }}<span class="reg_error" id="password2_err">{{ errors.password1.0 }}</span>
      </div>

    <div >
        <label for="password2">确认密码</label>
        {{ register_form.password2 }}<span class="reg_error" id="password2_err">{{ errors.password2.0 }}</span>
      </div>

    <div >
        <label for="email">邮箱</label>
        {{ register_form.email }}<span class="reg_error" id="email_err">{{ errors.email.0 }}</span>
      </div>

    {#  显示用户图片 #}
   <div class="avatar">
        <label for="image">头像</label>
        <img src="{% static 'img/default.jpg' %}" alt="" id="image" width="100px">
        <input type="file" id="file_choose" class="av" name="avatar">
        <span class="reg_error" id="file_error"></span>
    </div>


    {#  验证码刷新  #}
    <div class="valid_code">
        <label for="valid_code">验证码</label>
        <span class="valid">{{ register_form.valid_code }}</span>
        <img  src="/captcha/" width="100" height="35" class="valid_img valid">
        <a id="refersh" class="valid">刷新</a>
        <span class="reg_error" id="valid_code_err">{{ errors.valid_code.0 }}</span>
      </div>


    <input type="submit" value="提交">
    <input type="reset" style="display: none" id="reset_btn">
</form>

</body>
<script>
    // 必须导入Jquery模块，图片更新后动态显示
    $('#file_choose').change(function () {
            // 1. 找到已更换的图片路径
            var reader = new FileReader();
            // 2. 从input标签中找到上传的文件对象, [0]是找到DOM对象
            var upload_file = $(this)[0].files[0];
            // 3. 处理上传的图片路径
            upload_file_url = reader.readAsDataURL(upload_file);
            // 4. 给reader对象绑定load事件
            reader.onload=function () {
                // 5. 取出result对象,里面包含图路径, 赋值给img的src路径,
                $('#image')[0].src = this.result
            }
    });

    // 验证码刷新
    $('#refersh').click(function () {
        // 取到img标签的DOM对象
        $('.valid_img')[0].src+='?'
    });

</script>
</html>
```

**views.py**：注册视图逻辑，且包括自定制验证码。

```
################################## 自定义验证码逻辑
from PIL import Image, ImageDraw, ImageFont
from io import BytesIO
from django.shortcuts import HttpResponse
from string import ascii_letters, digits
import random
from random import randint

def generate_code():
    """生成六位数随机验证码"""
    code = "".join(random.sample(ascii_letters + digits, 6))
    return code

def get_random_color():
    return (randint(0, 255), randint(0, 255), randint(0, 255))

def get_valid_img(request):
    code = generate_code()
    request.session['valid_code'] = code
    # 1. 生成图片,颜色随机
    img = Image.new(mode="RGB", size=(213, 35), color=get_random_color())
    draw = ImageDraw.Draw(img, mode='RGB')  # 生成绘板对象
    # 2. 向图片写入内容
    font = ImageFont.truetype("static/fonts/kumo.ttf", 36)  # 字体样式必须引入, 字体大小
    # 保证每次生成不同的问题,且位数保证6位
    draw.text([60, 0], code, color=get_random_color(), font=font)  # 参数,:坐标, 文字, 颜色, 字体样式
    # 3. 保存到内存
    f = BytesIO()
    img.save(f, 'png')
    # 4. 读取图片
    data = f.getvalue()
    #  方式5, 验证码更新,必须是局部刷新,点击刷新
    return HttpResponse(data)


################################# 用户注册视图逻辑
from app01.forms import RegisterForm
from django.shortcuts import render
from app01.models import UserInfo

def register(request):
    if request.method == "GET":
        register_form = RegisterForm(request)
        return render(request, 'register.html', {
            'register_form': register_form,
        })

    elif request.method == 'POST':
        register_form = RegisterForm(request, request.POST,request.FILES)
        if register_form.is_valid():
            username = register_form.cleaned_data.get('username', '')
            password = register_form.cleaned_data.get('password1', '')
            email = register_form.cleaned_data.get('email', '')
            file = request.FILES.get('avatar')
            UserInfo.objects.create_user(username=username, password=password, email=email, avatar=file,is_active=False)
            return HttpResponse('注册成功')

        errors = register_form.errors
        return render(request,'register.html',{'errors':errors,'register_form':register_form})
```

###### Ajax实现注册

###### django-simple-captcha模块

----------

## 用户登录
当`is_active=false`时，`auth.authenticate(username,passwod)`一直是返回none.

#### Ajax实现用户登录
**urls.py**:

```
from django.conf.urls import url,include
from app01 import views as app1_view

urlpatterns = [
    url(r'^login/', app1_view.my_login),
    url(r'^captcha/', app1_view.get_valid_img),
]
```

**views.py**

```
# ajax实现用户登录====================================
from django.contrib import auth
import json
from django.contrib.auth.hashers import make_password

def my_login(request):
    if request.method == "POST":
        errors = {}
        flag=True
        # 1,从session中获取本次请求生成的图片代码
        code = request.session.get("valid_code", '').upper()
        # 2. 获取用户提交的数据
        username = request.POST.get('username',"")
        pwd = request.POST.get('password',"")
        if not username:
            errors['password'] = '密码不能为空'
            flag=False
        if not username:
            errors['username'] = '用户名不能为空'
            flag=False
        valid_code = request.POST.get('valid_code',"")
        # 3. 判断验证码是否合格
        if valid_code.upper() != code:
            errors['valid_code']='验证码有误'
            flag=False

        # 4. 根据用户名和密码从数据库查询匹配的用户
        user = auth.authenticate(username=username, password=pwd)
        if user and flag==True:
            # 5. 找到用户,则创建或修改session信息, 修改为登录状态
            auth.login(request, user)
            return HttpResponse(json.dumps({'status': "success",'errors':{}}), content_type="application/json")
        errors['error_msg']='有户名或密码有误'

        return HttpResponse(json.dumps({'status': "fail", 'errors': errors,}),content_type="application/json")

    elif request.method == "GET":
        return render(request, 'login.html', {
        })
```

**login.html**:

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>登录页面</title>
    <script src="/static/js/jquery-3.3.1.js"></script>
    <style>
        .valid{
            vertical-align: middle;
        }
        .form-group{
            margin-bottom: 10px;
        }
        .error_tips{
            color: red;
            font-size: 10px;
        }
    </style>
</head>

<body>
    <form method="post" action="" class="post_form">
      <div class="form-group">
        <label for="username">用户名</label>
        <input type="text" class="form-control" id="username" name="username">
          <span id="error_username" class="error_tips"></span>
      </div>

      <div class="form-group">
        <label for="password">密码</label>
        <input type="password" class="form-control" id="password" name="password">
          <span id="error_password" class="error_tips"></span>
      </div>

        <div class="form-group">
            <label for="valid_code">验证码</label>
            <input type="text" class="valid" id="valid_code" name="valid_code">
            <img src="/captcha/" width="130" height="" class="valid_img valid">
            <a class="refresh valid">刷新</a>
            <span id="error_valid_code" class="error_tips"></span>

        </div>

        <input type="button" value="提交" id="ajax_submit_btn">
        <input type="reset" style="display: none" id="reset_btn">
        {% csrf_token %}
    </form>
</body>

<script>
{#    自行构造data信息#}
$('#ajax_submit_btn').click(function () {
    // 每次提交都会清空之间的错误信息
    　$('#error_username').text('');
   　$('#error_password').text('');
   　$('#error_valid_code').text('');
   　$('#error_tips').text('');

   // ajax发送数据
    $.ajax({
       url:'/login/',
       type:"POST",
       data: {
           'username':$('#username').val(), 'password': $("#password").val(),
           'valid_code':$('#valid_code').val(), 'path':$('#path').val(),
           "csrfmiddlewaretoken":$('[name="csrfmiddlewaretoken"]').val()
       },
       success:function (data) {
           if(data.status == 'success'){
               window.location.href= 'https://www.baidu.com';
           }
           else if(data.status == 'fail'){
                console.log(data.errors)
               $('#error_username').text(data.errors.username);
               $('#error_password').text(data.errors.password);
               $('#error_valid_code').text(data.errors.valid_code);
               $('#error_username').text(data.errors.error_msg);
           }
       }
   })
});

// 验证码刷新
$('.refresh').click(function () {
    // 取到img标签的DOM对象
    $('.valid_img')[0].src+='?'
});
</script>
</html>
```

## django froms实现密码找回
**两组功能**：忘记密码和重置密码．

#### 忘记密码
**app01.forms.py**：构建注册和密码重置表单的form，同样利用自定义错误信息和利用全局和局部钩子，在调用`is_valid()`方法时，会根据自定义的验证信息进行验证，再将错误信息封装到form.errors内．

```
from django import forms
from app01.models import UserInfo

# ==========================忘记密码页面
class ForgetPwdForms(forms.Form):
    email = forms.EmailField(max_length=30,error_messages={'required': '验证码不能为空'})
    valid_code = forms.CharField(min_length=6, error_messages={'required': '验证码不能为空', 'min_length': '至少为6位'},
                                 max_length=6, widget=widgets.TextInput(attrs={"placeholder": "验证码"}))

    def __init__(self, request, *args, **kwargs):
        super(ForgetPwdForms, self).__init__(*args, **kwargs)
        self.request = request

    def clean_email(self):
        email = self.cleaned_data['email']
        user = UserInfo.objects.filter(email=email)
        if user:
            return email
        raise ValidationError('该邮箱没有注册')

    def clean_valid_code(self):
        '''检测验证码是否匹配'''
        if self.cleaned_data["valid_code"].upper() == self.request.session["valid_code"].upper():
            return self.cleaned_data["valid_code"]
        else:
            print('验证码错误')
            raise ValidationError("验证码错误！")
```

**forget_pwd.html**：需要用户填写邮箱和验证码．

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>忘记密码</title>
    <style>
        .error_tips{
            color: red;
            font-size: 10px;
        }
    </style>
</head>
<body>
<form method="post" novalidate>
    {% csrf_token %}

    <div >
        <label for="email">邮箱</label>
        {{ forget_form.email }}<span class="error_tips" id="email_err">{{ errors.email.0 }}</span>
      </div>

    {#  验证码刷新  #}
    <div class="valid_code">
        <label for="valid_code">验证码</label>
        <span class="valid">{{ forget_form.valid_code }}</span>
        <img  src="/captcha/" width="100" height="35" class="valid_img valid">
        <a id="refersh" class="valid">刷新</a>
        <span class="error_tips" id="valid_code_err">{{ errors.valid_code.0 }}</span>
      </div>

    <input type="submit" value="发送邮件">
</form>

</body>
</html>
```


**views.py**：需要通过邮箱发送邮件，类似与链接`http://127.0.0.1:8000/reset_pwd/IUMp7GH3KW94mTYdxfVcoyN21Bjs5FPS`．

```
from django.views import View
from app01.forms import ForgetPwdForms,ResetPwdForms
from django.shortcuts import HttpResponse,redirect
from app01.models import EmailValidCode
from django.contrib.auth.hashers import make_password

def generate_email_code():
    """生成32位数随机验证码"""
    code = "".join(random.sample(ascii_letters + digits, 32))
    return code

from django.core.mail import send_mail  # django自带的邮件发送模块
from pro_2.settings import EMAIL_FROM

def send_email(code,email):
    """发送邮件"""
    email_title = '博客忘记密码'
    email_body = '请点击下面的链接重置密码: http://127.0.0.1:8000/reset_pwd/{0}'.format(code)
    # 固定格式书写
    send_status = send_mail(email_title, email_body, EMAIL_FROM, [email])
    if send_status:
        print('发送成功')

class ForgetPwdView(View):
    def get(self, request):
        forget_form = ForgetPwdForms(request)
        return render(request, 'forget_pwd.html',{
            'forget_form':forget_form,
        })

    def post(self, request):
        forget_form = ForgetPwdForms(request,request.POST)
        if forget_form.is_valid():
            email = forget_form.cleaned_data['email']
            user = UserInfo.objects.filter(email=email)
            if user:
                # 生成邮箱验证码记录
                code = generate_email_code()
                email_code = EmailValidCode(code=code,email=email)
                email_code.save()
                # 发送邮件
                send_email(email=email,code=code)
                return HttpResponse('请前往邮箱查收!')

        errors = forget_form.errors
        return render(request, 'forget_pwd.html', {'errors': errors, 'forget_form': forget_form})
```
**setting.py**增加以下配置，不过密码需要自己百度方法．

```
EMAIL_HOST = "smtp.qq.com"
EMAIL_PORT = 25
EMAIL_HOST_USER = 'qq邮箱手动填入'
EMAIL_HOST_PASSWORD = 'qgmlmnhulqupbdij'
EMAIL_USE_TLS = True
EMAIL_FROM = EMAIL_HOST_USER
```

####  密码重置功能
**自定义的forms.py：**

```
from django import forms
from app01.models import UserInfo

class ResetPwdForms(forms.Form):
    password1 = forms.CharField(min_length=6, max_length=20,
                                error_messages={'required':'密码不能为空','min_length':'至少为6位','max_length':'最多为20位'})
    password2 = forms.CharField(min_length=6, max_length=20,
                                error_messages={'required':'密码不能为空','min_length':'至少为6位','max_length':'最多为20位'})

    def __init__(self, request, *args, **kwargs):
        super(ResetPwdForms, self).__init__(*args, **kwargs)
        self.request = request

    def clean_password2(self):
        '''自定义密码检测'''
        # if len(self.cleaned_data['password2']) < 6:
        #     raise ValidationError('密码长度小于六位')
        if self.cleaned_data['password2'].isalpha() or self.cleaned_data['password2'].isdigit():
            raise ValidationError('密码不能全为数字或者字母')
        else:
            return self.cleaned_data['password2']

    def clean_password1(self):
        '''自定义密码检测'''
        # if len(self.cleaned_data['password1']) < 6:
        #     raise ValidationError('密码长度小于六位')
        if self.cleaned_data['password1'].isalpha() or self.cleaned_data['password1'].isdigit():
            raise ValidationError('密码不能全为数字或者字母')
        else:
            return self.cleaned_data['password1']

    def clean(self):
        '''密码一致性检测'''
        if self.cleaned_data.get('password1') == self.cleaned_data.get('password2'):
            return self.cleaned_data
        else:
            raise ValidationError("密码不一致")
```
**前端页面password_reset.html**：

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>重置密码</title>
</head>
<body>

<form method="post" novalidate>
    {% csrf_token %}

     <div >
        <label for="password1">密码</label>
          {{ pwd_form.password1 }}<span class="reg_error" id="password2_err">{{ errors.password1.0 }}</span>
      </div>

    <div >
        <label for="password2">确认密码</label>
        {{ pwd_form.password2 }}<span class="reg_error" id="password2_err">{{ errors.password2.0 }}</span>
      </div>

    <input type="submit" value="发送邮件">
</form>

</body>
</html>
```
**路由配置urls**：

```
from django.conf.urls import url,include
from app01 import views as app1_view

urlpatterns = [
    url(r'^reset_pwd/(\w+)/', app1_view.reset_pwd,name='reset_pwd'),
]
```

**视图逻辑views.py**：通过url接收参数，即为验证码，再通过表记录查询出对应的邮箱，从而找出user信息，进行密码修改．

```
from app01.forms import ForgetPwdForms,ResetPwdForms
from django.shortcuts import HttpResponse,redirect
from app01.models import EmailValidCode

def reset_pwd(request, code):
    if request.method=='GET':
        pwd_form = ResetPwdForms(request)
        return render(request,'password_reset.html',{'pwd_form':pwd_form})

    if request.method=='POST':
        pwd_form = ResetPwdForms(request,request.POST)
        if pwd_form.is_valid():
            password = pwd_form.cleaned_data['password1']
            # 取用户信息
            email_code = EmailValidCode.objects.filter(code=code)
            if email_code:
                email=email_code[0].email
                user = UserInfo.objects.filter(email=email).first()
                user.password=make_password(password)
                user.save()
                return redirect('/login/')

        errors = pwd_form.errors
        return render(request, 'password_reset.html', {'pwd_form':pwd_form,'errors':errors})
```
index.html：在主页面设置链接．

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>主页面</title>
</head>
<body>

<h1>当前用户{{ request.user.username }}</h1>

<a href="{% url 'forget_pwd' %}">忘记密码</a>
<a href="{% url 'login' %}">登录</a>
<a href="{% url 'register' %}">注册</a>

</body>
</html>
```

## 分页组件开发
**思路**:
1. 可以采用输入url传输当前的页数, 例如: `127.0.0.1/index.html/?page=1`,获取第一页的内容, 随后在视图函数通过`int(request.GET.get('path'))`来取出当前要获取的页码, 若规定每页显示10条数据, 当前页为1的话, 要显示的数据索引为`[0, 10]`, 取出对应的数据列表,返回给前端;
2. 在前端建立a标签列表, 配置url的page参数即可, 缺点是不能动态生成;
3. 在后端建立a标签列表字符串, 使其自动生成, 传输到前端使用`make_safe`, 此过程涉及到计算最大页码数, 根据最大数据量和每页显示的数据计算即可;
4. 当前页高亮显示;
5. 配置上一页和下一页;
6. 固定页码数显示, 若数据量很大的话,会造成页码过多,所以要显示最大显示的页码数;
7. 整合成类

#### 自定义pagenator类
自定义分页类Paginator，样式采用bootstrap．

```
class Paginator(object):
    def __init__(self, current_page=1, total_count=0, show_page_num=5,per_page_count=0,obj_lst =[]):
        """
        :param current_page: 当前页码
        :param total_count: 数据总条数
        :param per_page_count:  每页显示的条数
        :param show_page_num:   显示页码数
        """
        self.current_page = int(current_page)
        self.per_page_count = int(per_page_count)
        self.show_page_num = int(show_page_num)
        self.total_count = int(total_count)
        self.obj_lst = obj_lst
        a, b = divmod(self.total_count, self.per_page_count)
        if b:
            total_pages = a + 1
        else:
            total_pages = a
        self.total_pages = total_pages  # 最大页数

    @property
    def start(self):
        """
        :return: 返回当前页的第一个数据的索引, 配合end方法使用,取出当前页的所有数据;
        """
        return (self.current_page - 1) * self.per_page_count

    @property
    def end(self):
        """
        :return: 返回当前页的最后一套数据的数据的索引
        """
        return self.current_page * self.per_page_count

    @property
    def page_data(self):
        return self.obj_lst[self.start:self.end]

    @property
    def html_str(self):
        """ 生成分页文本"""
        # 1. 制作上一页和下一页---------------------------------------
        if self.current_page <= 1:
            prev_p = '<li class="disabled long"><a href="#">上一页</a></li>'
        else:
            prev_p = '<li class="long"><a href="?page=%s">上一页</a></li>' % (self.current_page - 1)

        if self.current_page >= self.total_pages:
            next_p = '<li class="disabled long"><a href="#">下一页</a></li>'
        else:
            next_p = '<li class="long"><a href="?page=%s">下一页</a></li>' % (self.current_page + 1)

        # 2. 确保显示的页码数相同-----------------------------难点
        if self.total_pages < self.show_page_num:
            pager_start,pager_end=1,self.show_page_num+1

        else:
            if self.current_page<=self.show_page_num:
                pager_start,pager_end=1,self.total_pages+1
            else:
                pager_start = self.current_page - self.show_page_num
                pager_end = self.current_page + self.show_page_num+1
                if self.current_page + self.show_page_num+1 > self.total_pages:
                    pager_start = self.total_pages - self.show_page_num
                    pager_end = self.total_pages

        # 3. 制作当前页的页码显示------------------------------------
        page_list = []
        for i in range(pager_start, pager_end+1):
            if i == self.current_page:
                # 当前页高亮显示
                page_list.append('<li class="active"><a href="?page=%s">%s</a></li>' % (i, i))
            else:
                page_list.append('<li><a href="?page=%s">%s</a></li>' % (i, i))

        # 4. 将页码拼接成字符串
        page_str = '  '.join(page_list)
        # 5. 加上上一页和下一页
        page_str = prev_p + page_str + next_p
        return page_str
```
views.py使用：

```
class CourseListView(View):
    def get(self,request):
        sort = request.GET.get('sort', '')
        all_courses = Course.objects.all()
        page_num = request.GET.get('page')
        if not page_num:page_num=1
        p = Paginator(obj_lst=all_courses,per_page_count=1,total_count=all_courses.count(),current_page=page_num)
        page_data = p.page_data
        pager_str = p.html_str
        return render(request, 'course-list.html', locals())
```

前端页面显示：用到bootstrap布局样式．

```
<nav class="pageturn">
    <ul class="pagination">
        {{ pager_str|safe }}
    </ul>
</nav>
```
路由配置：

```
from django.conf.urls import url,include
from app01 import views as app1_view

urlpatterns = [
]
```

**函数逻辑分析**：

```
１０１条数据
每页１０条数据
当前页	ｎ


页码		数据
１		［０：１０］
２		［１０：２０］
３		［２０：３０］
．．．
９		［８０：９０］
１０		［９０：１００］
１１		［１０１］

通过以上的数据计算出总共的页数
	101/10=10.1
	

上一页　１　２　３　４　５　６　７ ８　９　１０　１１　下一页


目标：
	根据页码ｎ取出对应页的所有数据
		例如：ｎ＝１０＞＞　Book.objects.all()［８０：９０］；
	判断是否存在上一页和下一页
		ｎ<=1
			没有上一页
		
		n>=total_page
			没有下一页
	显示的页码个数	
		当数据量很大的时候，例如根据计算页数达到１００甚至更多，那么也不能全部显示，怎么办？
		规定最多显示９个页码：show_page_num=9
			当计算后的　total_pages　>9时，按照show_page_num为准；
			若页码total_pages<=９时，那么直接显示即可；
			
			
			# 需要重新组织标签字符串，有点难度，先不采用	
			
			'''
			例如：total_pages＝100，show_page_num＝5
			
			上一页　 １　２　３　４　５　... 100 下一页
			
			上一页　１　...4　５ 6 7 8 ... 100 　下一页
			
			上一页　１　...96　97 98 99 100 　下一页
			
			
			if current_page_num < 5:
				上一页　 １　２　３　４　５　... 100 下一页
					
			elif 5 < current_page_num < total_pages - 4:
				上一页　１　...4　５ 6 7 8 ... 100 　下一页
			
			elif total_pages - 4 <= current_page_num <= total_pages:
				上一页　１　...96　97 98 99 100 　下一页
			'''
			
			total_pages＝11，show_page_num＝5
			
			
			上一页　 １　２　３　４　５ 下一页
			
			上一页　 2　3　4　5　6  下一页
		
			half_show_page_num = show_page_num / 2
			page_start = current_page - half_show_page_num	
			pager_end = current_page + half_show_page_num　+ 1
			
			例如：
				c_page = 5
				p_s = 5-2=3
				p_e = 5+2+1=8
				
				7 8 9 10 11
```


----------

## 多级评论树

#### 评论列表功能函数
此推导方法为多级递归通用方法!

```
# 传入的参数形式要求
comment_list = comment_list = [
    {'id': 1, 'content': '1111', 'parent_id': None, 'children_contents':[]},
    ...
]

# 转换成嵌套结果列表
def transform_list(comment_list):
    comment_dict = {}
    for d in comment_list:
        id = d.get('id')
        comment_dict[id] = d
        
    for k in comment_dict:
        parent_id = comment_dict[k]['parent_id']
        if parent_id:
            comment_dict[parent_id]['children_contents'].append(comment_dict[k])

    res_list = []
    for i in comment_dict:
        if not comment_dict[i]['parent_id']:
            res_list.append(comment_dict[i])
    return res_list

# 结果形式
res_list = [{
	'id': 8,
	'content': '8888',
	'parent_id': None,
	'children_contents': []
}, ...]

```

#### 推倒过程
1. 模拟取出某文章的所有评论的部分信息如下,

    ```
    comment_list = [
        {'id': 1, 'content': '1111', 'parent_id': None, 'children_contents': []},
        {'id': 2, 'content': '2222', 'parent_id': None, 'children_contents': []},
        {'id': 3, 'content': '3333', 'parent_id': 1, 'children_contents': []},
        {'id': 4, 'content': '4444', 'parent_id': 2, 'children_contents': []},
        {'id': 5, 'content': '5555', 'parent_id': 4, 'children_contents': []},
        {'id': 6, 'content': '6666', 'parent_id': 3, 'children_contents': []},
        {'id': 7, 'content': '7777', 'parent_id': 6, 'children_contents': []},
        {'id': 8, 'content': '8888', 'parent_id': None, 'children_contents': []},
    ]
    ```

2. 进一步构建数据结构, `{1: {'id':1, ...}, 2: {'id':2, ...},}`

    ```
    comment_dict = {}
    
    for d in comment_list:
        id = d.get('id')
        comment_dict[id] = d
    
    '''
    {1: {'id': 1, 'content': '...', 'parent_id': None, 'children_contents': []},
    2: {'id': 2, 'content': '...', 'parent_id': None, 'children_contents': []},
    3: {'id': 3, 'content': '...', 'parent_id': 1, 'children_contents': []},
    4: {'id': 4, 'content': '...', 'parent_id': 1, 'children_contents': []},
    5: {'id': 5, 'content': '...', 'parent_id': 4, 'children_contents': []},
    6: {'id': 6, 'content': '...', 'parent_id': 3, 'children_contents': []},
    7: {'id': 7, 'content': '...', 'parent_id': 6, 'children_contents': []},
    8: {'id': 8, 'content': '...', 'parent_id': None, 'children_contents': []},
    }
    ```


3. 若存在父评论将每个评论放进其`parent_id`对应的`children_contents`列表中

    ```
    for k in comment_dict:
        parent_id = comment_dict[k]['parent_id']
        if parent_id:
            comment_dict[parent_id]['children_contents'].append(comment_dict[k])
    
    '''
    {1: {'id': 1, 'content': '...', 'parent_id': None, 'children_contents': [
        {'id': 3, 'content': '...', 'parent_id': 1, 'children_contents': [],
        {'id': 4, 'content': '...', 'parent_id': 1, 'children_contents': []}
        ]},
        
    2: {'id': 2, 'content': '...', 'parent_id': None, 'children_contents': []},
    3: {'id': 3, 'content': '...', 'parent_id': 1, 'children_contents': [
        {'id': 6, 'content': '...', 'parent_id': 3, 'children_contents': []},
    ]},
    
    4: {'id': 4, 'content': '...', 'parent_id': 1, 'children_contents': [
        {'id': 5, 'content': '...', 'parent_id': 4, 'children_contents': []},
        ]},
        
    5: {'id': 5, 'content': '...', 'parent_id': 4, 'children_contents': []},
    6: {'id': 6, 'content': '...', 'parent_id': 3, 'children_contents': [
        {'id': 7, 'content': '...', 'parent_id': 6, 'children_contents': []},
    ]},
    
    7: {'id': 7, 'content': '...', 'parent_id': 6, 'children_contents': []},
    8: {'id': 8, 'content': '...', 'parent_id': None, 'children_contents': []},
    }
    ```

4. 筛选出所有的根评论, 整理成列表形式

    ```
    res_list = []
    for i in comment_dict:
        if not comment_dict[i]['parent_id']:
            res_list.append(comment_dict[i])
    
    res_list = [
        {
    	'id': 1,
    	'content': '1111',
    	'parent_id': None,
    	'children_contents': [{
    		'id': 3,
    		'content': '3333',
    		'parent_id': 1,
    		'children_contents': [{
    			'id': 6,
    			'content': '6666',
    			'parent_id': 3,
    			'children_contents': [{
    				'id': 7,
    				'content': '7777',
    				'parent_id': 6,
    				'children_contents': []
    			}]
    		}]
    	}]
    },
        {
    	'id': 2,
    	'content': '2222',
    	'parent_id': None,
    	'children_contents': [{
    		'id': 4,
    		'content': '4444',
    		'parent_id': 2,
    		'children_contents': [{
    			'id': 5,
    			'content': '5555',
    			'parent_id': 4,
    			'children_contents': []
    		}]
    	}]
    },
        {
    	'id': 8,
    	'content': '8888',
    	'parent_id': None,
    	'children_contents': []
    }]
    ```


6. 遍历根评论(最关键)

    ```
    ## 要实现的结构
        根评论1 
            子评论1
            子评论1
        
        根评论2
            子评论3
            子评论4
        
        跟评论3
            子评论5        
            子评论6
    
    # 实现函数
    def get_content(list):
        for d in list:
            print(d['content'])
            if d['children_contents']:
                # 递归,调用自身
                get_content(d['children_contents'])
    
    get_content(res_list)
    
    # 打印的结果
    1111
    	3333
    		6666
    			7777
    2222
    	4444
    		5555
    8888
    ```

#### Ajax动态生成多级评论树

```
# 前端页面代码

<div class="blog_comment">
    <div class="comment_title">评论列表</div>
    <hr>

    <div class="list-group comment_form">
    
    </div>

    <script>
        # 处理评论类别函数函数,传入一系列评论根节点集合
        function comment_tree(comment_list) {
            var html = "";

            #  循环遍历根节点,内部参数为 索引 和 值
            $.each(comment_list, function (k, v) {
                # 准备组合一个评论节点
                var comment_item = '<div class="comment_item">';

                # 构建评论内容
                var temp = "<div class='content'>
                <span>{0}{1}</span></div>".format(
                v['nid'], v['content']);

                comment_item += temp;

                # 判断内部是否有子评论,有子评论则取出来, 整合成<div class='content'>
                if (v['children_contents']){
                    // 最关键的一步
                    comment_item += comment_tree(v['children_contents'])
                }
                # 最后闭合这个comment_item节点
                comment_item += "</div>";

                html += comment_item
            });

            return html
        }

        # 加载完毕触发ajax事件,再次向server发送请求, 接受处理好的评论列表
        $(function () {
            alert(1);
            $.ajax({
                url: "",
                type: 'GET',
                success: function (data) {

                    # 将data从string解析成原来的列表结构
                    var my_comment_list = JSON.parse(data);
                    # ajax接收后端传入的评论列表
                    s = comment_tree(my_comment_list);
                    $('.comment_form').append(s)
                }
            })
        });

    </script>

</div>
```


#### 自定义标签生成多级评论树

```
# urls.py========================================
url(r'^p/(\d{1,5})/', views.article_detail_page, name='article'),


# views.py======================================
def article_detail_page(request, pk):
    article = Article.objects.filter(nid=int(pk)).first()
    if not article:
        return HttpResponse('<h1>资源页面不存在</h1>')

    return render(request, 'article_detail_2.html', {
        'pk': pk,
        'article': article,
    })

# 前端页面======================================
# 其余的地方不变
{% user_comment request pk %}
 
# my_tags.py=====================================
from my_blog.models import Article
from django.shortcuts import HttpResponse, render, redirect
from ..utils import transform_list

# 以下流程直接参考权限项目的菜单生成

# 根据文章id获取文章评论,且进行处理
def process_menu_data(pk):
    article = Article.objects.filter(nid=int(pk)).first()
    if not article:
        return HttpResponse("<h1>资源不存在!</h1>")
    comment_list = list(article.comment_set.all().values('nid', 'content', 'user_id', 'parent_id_id'))
    comment_list = transform_list(comment_list)
    return comment_list

# 根据信息列表生成评论标签字符串
def produce_html(comment_list):
    html = ''
    tpl1 = """
               <div class="comment_item">
                   <div class="comment-header">{0}{1}</div>
                   <div class="comment-body">{2}</div>
               </div>
           """
    for item in comment_list:
        if item['children_contents']:
            html += tpl1.format(item['user_id'], item['content'].strip(),
                                produce_html(item["children_contents"]))
        else:
            html += tpl1.format(item['user_id'], item['content'].strip(), '')
    return html


from django.utils import safestring

#  自定义标签, 直接在模板中渲染出评论列表
@register.simple_tag
def user_comment(pk):
    data = process_menu_data(pk)
    html = safestring.mark_safe(produce_html(data))
    return html
```


#### ajax实现评论

```
# 标签
<div id="add-form" class="comment_con"><span class="comment_title">提交评论</span>
    <textarea id="comment_input" cols="30" rows="10" >
    </textarea>
    
    <p>
       <input type="button" value="submit" id="comment_submit_btn" class="btn btn-success">
    </p>
</div>


<script>
var parent_comment_id = "";  // 设置全局变量,当点击回复按钮则赋值为点击的评论的id;
var father_comment_username = ''; // 设置父级标签的全局变量,同样是点击回复按钮则设置对应的值;
var father_comment_content = '';

// 回复评论事件
$('.comment_list').on('click', '.reply_btn', function () {
    # 1.取出该条评论的id值,即为class属性值, 定位到父级标签后,就可以取出父级评论的内容;
    parent_comment_id = $(this).next().attr('class');

    # 2.点击回复按钮, 则设置father_comment_username的值;
    father_comment_username = $(this).siblings().eq(0).text();

    # 3.给文本框添加回复的用户名内容, 仅用于在前端显示, 注意此处使用text()赋值会出现问题;
    $('#comment_input').val('@'+father_comment_username+'\n');
    
    # 取出该评论的内容供后面使用
    father_comment_content = $(this).siblings().eq(4).children().eq(1).text();});

    # 文章点赞;
    $('#favor_btn').click(function () {
        {% if request.user.is_authenticated %}
             $.ajax({
            url:'/blog/favor/',
            type: 'post',
            data: {'article_id':{{ article.nid }},
                   'csrfmiddlewaretoken':$('[name="csrfmiddlewaretoken"]').val()},
            success: function (data) {
                if(data.status=='success'){
                    $('#article_num').text(data.poll_num)
                }
            }});
        {% else %}
            window.location.href='/login?path='+$('#request_path').val();
        {% endif %}});


# 增加文章评论
  $("#comment_submit_btn").click(function () {
      // 1. 取出换行符 \n 的索引位置
      var index=$("#comment_input").val().indexOf("\n");

      // 2. 取出真正的文本内容,字符串切片,js语法,从第二行开始,切片所有的内容
      var comment_content=$("#comment_input").val().substr(index+1);
      alert(comment_content);

      {% if request.user.is_authenticated %}
        $.ajax({
           url:"/blog/comment/",
           type:"post",
           data:{"csrfmiddlewaretoken":$("[name='csrfmiddlewaretoken']").val(),
                 "article_id":{{ article.nid }},
                 "comment_content":comment_content,
                 "parent_comment_id":parent_comment_id
           },
           success:function (data) {
                // 判断是否是通过回复按钮来添加评论的,注意必须在最后清空father_comment_username这个变量
               var temp=father_comment_username;
               s='<li class="list-group-item comment_item"><a href="">{0}</a><a href="">{1}</a><a href="" class="pull-right">&nbsp;支持</a><a href="#comment_content" class="pull-right reply_btn">回复</a><span class="{2}"></span> <div> <span>{3}</span> <p>{4}</p></div> </li>';
               if (temp){father_comment_username="<a>@</a>"+temp}

               // js中利用字符串拼接
               s=s.format('{{ request.user.username }}',
                        data.comment_createTime,
                        parent_comment_id,
                        father_comment_username,
                        comment_content);

               $(".comment_list").append(s);
               $("#comment_input").val("");

               // 关键点, 每次走完此处必须对全局变量清零
               father_comment_username="";
               parent_comment_id=0;
               father_comment_content=''
        }
   });

      {% else %}
       location.href="/login?path={{ request.path }}";
      {% endif %}
  });

</script>


// views.py
def user_comment(request):
    """方法1, 直接在前端操作评论内容"""
    user_id = request.user.nid
    article_id = request.POST.get("article_id")
    comment_content = request.POST.get("comment_content").strip()
    # 若评论内容为空,则不添加任何信息
    if not comment_content:
        return HttpResponse('noy ok')

    # 1. 查看是否是通过回复(有父评论)发送还是直接评论发送
    if request.POST.get("parent_comment_id"):
        # 2. 获取该评论的父级评论id并保存记录
        c = int(request.POST.get("parent_comment_id"))
        comment_obj = Comment.objects.create(article_id=article_id, content=comment_content, user_id=user_id,
                                             parent_id_id=c)
    else:
        comment_obj = Comment.objects.create(article_id=article_id, content=comment_content, user_id=user_id)

    from django.db.models import F
    # 3. 对评论数量自加操作
    Article.objects.filter(nid=article_id).update(comment_num=F("comment_num") + 1)

    # 只传输创建时间过去
    response_ajax = {"comment_createTime": str(comment_obj.create_time)[:16], }  # 很关键,不去毫秒!
    return HttpResponse(json.dumps(response_ajax), content_type='application/json')
```

## Xadmin后台管理

#### django自带的admin系统
杀手级功能: 在新建项目时候已经自动生成!
1、创建超级用户:`python manage.py createsuperuser`
2、登录admin系统
3、配置文件修改

```
LANGUAGE_CODE = 'zh-hans'       // 修改后台界面语言为汉字
TIME_ZONE = 'Asia/Shanghai'     // 时区设置
USE_TZ = False                  // 
```
4、注册表: 进入app下的`admin.py`文件

```
from .models import UserProfile
class UserProfileAdmin(admin.ModelAdmin):
    pass

admin.site.register(UserProfile, UserProfileAdmin)
```

5、刷新admin页面即可

#### XAdmin后台
继承自admin.
1. 安装xadmin模块, 同时也会安装相关依赖包: `pip install xadmin`, 若安装出现错误,见安装xadmin
2. 在`setting.py`将`xadmin`和`crispy_forms`放进`INSTALLED_APPS`中;
3. 同步xadmin自带的表: `python manage.py migrate`
4. 修改`url.py`

    ```
    import xadmin
    urlpatterns = [
        url(r'^xadmin/', xadmin.site.urls),
    ]
    ```

#### PIP安装XAdmin

```
Downloading xadmin-0.6.1.tar.gz (1.0MB)
    100% |████████████████████████████████| 1.0MB 547kB/s
    Complete output from command python setup.py egg_info:
    Traceback (most recent call last):
      File "<string>", line 1, in <module>
      File "C:\Users\leo\AppData\Local\Temp\pip-build-thid_cll\xadmin\setup.py", line 11, in <module>
        long_description=open('README.rst').read(),
    UnicodeDecodeError: 'gbk' codec can't decode byte 0xa4 in position 3444: illegal multibyte sequence

    ----------------------------------------
Command "python setup.py egg_info" failed with error code 1 in C:\Users\leo\AppData\Local\Temp\pip-build-thid_cll\xadmin\
```

README.rst这个文件的编码有问题，可以内容没什么重要的，
1.直接到github上下载安装包，下载地址：`https://github.com/sshwsfc/xadmin`;
2.然后新建一个txt空文件，把文件名改成README.rst，替换原来的文件下载安装包，下载zip压缩文件;
3.直接进入压缩包所在的目录安装: `pip install xadmin-master.zip`.


###### 源码安装Xadmin
由于xadmin源码是最新版本的,还可以自定义功能,所以推荐源码安装
1. 同样,github下载源码:`https://github.com/sshwsfc/xadmin`;
2. 解压,取出xadmin文件夹,放在项目根目录;
3. 新建`extra_apps`文件夹, 将xadmin文件夹放进去;
4. 由于django自带查找的功能,可以将文件夹mark为source_root;
5. 同样配置文件设置: `sys.path.insert(1, os.path.join(BASE_DIR, 'extra_apps'))`


#### Xadmin中App的Model注册
类似admin的model注册;
1、每个app下新建`adminx.py`文件,xadmin会默认查询此文件;
2、写入以下代码:

```
// 修改后刷新页面即可
import xadmin
from course.models import Course, Chapter, Video, CourseResouces

class CourseAdmin(object): // 继承object
    # 扩展功能1: 选择显示的字段
    list_display = ['name', 'mobile', 'course_name']
    
    # 扩展功能2: 添加字段搜索,筛选功能
    search_fields = ['name', 'mobile', 'course_name']  # 某些字段不能加,例如时间
    
    # 扩展功能3: 界面自带导出功能, 可以导出多种格式

    # 扩展功能4: 过滤器
    list_filter = ['name', 'mobile', 'course_name']
    
    # list_display = ['name', 'course', 'course']
    # search_fields = ['name', 'course', 'course']
    # list_filter = ['name', 'course', 'course']
    
xadmin.site.register(Course, CourseAdmin)
```
3、注意:**user表会自动生成,无须注册!**
4、若有多个app的话,添加字段需要仔细点!


#### Xadmin全局配置
先选择一个app下的adminx.py文件, 随后进行注册操作.

**主题修改**

```
from xadmin import views

class BaseSetting(object):
    enable_themes = True
    use_bootswatch = True
     menu_style = "accordion"  // 折叠左侧app菜单

xadmin.site.register(views.BaseAdminView, BaseSetting)
```

**全局页头和页脚配置**

```
class GlobalSetting(object):
    site_title = '学习在线后台管理系统'
    site_footer = '学习在线'

xadmin.site.register(views.CommAdminView, GlobalSetting)
```

**修改左侧菜单App显示名称**

```
// appname.apps.py
class CourseConfig(AppConfig):
    name = 'appname'
    verbose_name = '要显示的名称'

// appname.__init__.py
default_app_config = "appname.apps.CourseConfig"
```

**最终结果展示**
![](http://oyhijg3iv.bkt.clouddn.com/Xadmin%E5%90%8E%E5%8F%B0%E7%AE%A1%E7%90%86%E7%95%8C%E9%9D%A2.png)


## 项目部署

快速生成requirement.txt的安装文件：`pip freeze > requirements.txt`；
安装所需要的文件：`pip install -r requirement.txt`；

