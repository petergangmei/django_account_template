from django.contrib.auth.tokens import default_token_generator
from django.utils import timezone
from datetime import timedelta
import random
import jwt
from django.core.mail import EmailMultiAlternatives

from django.conf import settings
from django.http import JsonResponse
from django_thread import Thread

def generate_otp(email):
    # Generate the OTP using default_token_generator from Django
    otp =  ''.join([str(random.randint(0, 9)) for _ in range(6)])
    
    # Calculate the expiration time by adding 5 minutes to the current time
    expiration_time = timezone.now() + timedelta(minutes=25)

    payload = {
        'email': email,
        'otp': otp,
        'exp': expiration_time
    }
    token = jwt.encode(payload,'your-secret-key', algorithm='HS256')
    
    # Return the OTP and the expiration time as a tuple
    return otp, expiration_time, token


def send_email(data):
        subject = data['subject']
        body_text = ''
        body_html = data['body']
        to_email = data['email']

        class send_email_thread(Thread):
            def run(self):
                from_email = settings.EMAIL_HOST_USER
                recipient_list = [to_email]
                email = EmailMultiAlternatives(subject, body_text, from_email, recipient_list)
                email.attach_alternative(body_html, "text/html")
                email.send()
                
        thread = send_email_thread()
        thread.start()
        print('email sent')
        return JsonResponse({'success':True})