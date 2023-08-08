from django.shortcuts import render,redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.contrib import messages
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from . models import PasswordReset, Profile
from django.template.loader import render_to_string
from core.utils import generate_otp
from django.utils import timezone
import jwt
from core.utils import send_email
from django.conf import settings


def index(request):

    return render(request, 'account/index.html')


# registered view, only logged in user will be able to access the profile
# if it's not redirecting correctly, add LOGIN_URL = '/account/login' in setting.py
@login_required
def profile(request):

    return render(request, 'account/profile.html')

def forgot_password(request):
    if request.method == 'POST':
        #  check if the email exist in our database
        try:
           userObj =  User.objects.get(username=request.POST.get('email'))
           otp, expiry,token = generate_otp(request.POST.get('email'))

           try:
                pswd = PasswordReset.objects.get(user=userObj, valid_til__gt = timezone.now(), password_updated=False)
                payload = jwt.decode(token, 'your-secret-key', algorithms=['HS256'])
                uemail = payload['email']
                otp = payload['otp']
                exp = payload['exp']
                
                mail_subject = "Password Reset Email"
                link_address = settings.BASE_URL+"reset-password/?token="+token
                mail_body = render_to_string('email_templates/password_reset.html', {'link': link_address})
                data ={
                    'subject':mail_subject,
                    'body':mail_body,
                    'email':request.POST.get('email')
                }
                send_email(data)
                pswd.otp = otp
                pswd.save()
                messages.success(request, 'Password reset email sent')

           except PasswordReset.DoesNotExist:
                mail_subject = "Password Reset Email"
                link_address = settings.BASE_URL+"reset-password/?token="+token
                mail_body = render_to_string('email_templates/password_reset.html', {'link': link_address})
                data ={
                    'subject':mail_subject,
                    'body':mail_body,
                    'email':request.POST.get('email')
                }
                send_email(data)
                PasswordReset.objects.create(user=userObj, otp=otp, valid_til=expiry,token=token)
                messages.success(request, 'Password reset email sent')
           return redirect(reverse('account:forgot-password'))

        except User.DoesNotExist:
            messages.warning(request, 'Your email is not registered with us.')
            return redirect(reverse('account:forgot-password'))
    else:
        if request.user.is_authenticated:
            return redirect(reverse('account:profile'))     
        return render(request, 'account/forgot_password.html')
    
def password_reset(request):
    if request.method == 'POST':
        pass1 = request.POST.get('password1')
        pass2 = request.POST.get('password2')
        payload = jwt.decode(request.POST.get('token'), 'your-secret-key', algorithms=['HS256'])
        email = payload['email']
        otp = payload['otp']
        exp = payload['exp']
        userObj = User.objects.get(username=email)
        
        if pass1 is not None and len(pass1) < 5:
            messages.warning(request, 'Please enter alteast 5 digit password.')
            return redirect(reverse('account:reset-password')+"?token="+request.POST.get('token'))
            # return redirect(reverse('account:reset-password',  kwargs={'token':request.POST.get('token')}))

        if pass1 != pass2:
            messages.warning(request, 'You have entered two diffent password.')
            return redirect(reverse('account:reset-password')+"?token="+request.POST.get('token'))
            # return redirect(reverse('account:reset-password',  kwargs={'token':request.POST.get('token')}))
        
        user = User.objects.get(username=email)
        user.password = make_password(pass1)
        user.save()
        pas = PasswordReset.objects.get(user=userObj, valid_til__gt=timezone.now(),password_updated=False)
        pas.password_updated = True
        pas.password = make_password(pass1)
        pas.save()
        messages.success(request, 'Password updated.')
        return redirect(reverse('account:profile'))
    else:
        try:
            token = request.GET.get('token')
            payload = jwt.decode(token, 'your-secret-key', algorithms=['HS256'])
            email = payload['email']
            otp = payload['otp']
            exp = payload['exp']
            userObj = User.objects.get(username=email)
            try:
                pas = PasswordReset.objects.get(user=userObj, valid_til__gt=timezone.now(),password_updated=False)
                if pas.password_updated is True:
                    messages.warning(request, 'This token has already been used.')    
                    return redirect(reverse('account:forgot-password'))
                context ={
                    'token':token,
                }
                return render(request, 'account/reset_password.html',context)

            except PasswordReset.DoesNotExist:
                messages.warning(request, 'This token is not valid anymore')
            # Check if OTP is valid and not expired
                return redirect(reverse('account:reset-password'))
        except jwt.ExpiredSignatureError:
            messages.warning(request, 'Token has expired')
            return redirect(reverse('account:forgot-password'))
        except jwt.DecodeError:
            messages.warning(request, 'Invalid token')
            return redirect(reverse('account:forgot-password'))
            return render(request, 'account/reset_password.html')
    
def account_register(request):
    if request.method == 'POST':
        # check if user email exist
        try:
            User.objects.get(username=request.POST.get('email'))        
            messages.warning(request, 'Email already exist!')
            return render(request, 'account/register.html')    
        except User.DoesNotExist:
            user = User.objects.create(username=request.POST.get('email'), password=make_password(request.POST.get('password')))
            messages.success(request, 'Account created success')
            mail_subject = "Welcome"
            link_address = settings.BASE_URL+"reset-password/?token="
            mail_body = render_to_string('email_templates/welcome_mail.html', {'link': link_address})
            data ={
                'subject':mail_subject,
                'body':mail_body,
                'email':request.POST.get('email')
            }
            send_email(data)
            login(request, user)
            return redirect(reverse('account:profile'))
    else:
        if request.user.is_authenticated:
                return redirect(reverse('account:profile'))
        return render(request, 'account/register.html')

def account_login(request):
        if request.method == 'POST':
            try:
                user = authenticate(username=request.POST.get('email'), password=request.POST.get('password'))        
                if user is not None:
                    login(request, user)
                    messages.success(request, 'Login success!')
                    return redirect(reverse('account:profile'))
                else:
                    messages.warning(request, 'Email or Password is incorrect!')
                    return render(request, 'account/login.html')
            except User.DoesNotExist:
                messages.success(request, "Email Doesn't exist")
        else:
            if request.user.is_authenticated:
                return redirect(reverse('account:profile'))
        
            return render(request, 'account/login.html')

def account_logout(request):
    logout(request)
    return redirect(reverse('account:login'))