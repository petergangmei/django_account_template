
> Welcome to Your Django Web App!

This is a sample Django template showcasing various components:

    Account registration
    Login
    Forgot password
    Sending reset password emails
    Welcome emails

For your email to work, you will need to add .env file in the mail folder where manage.py is located

Add the below detail

EMAIL_HOST = 'your email host (get it from your email service provider)'

EMAIL_USE_TLS = False

EMAIL_PORT = 465

EMAIL_USE_SSL = True

EMAIL_HOST_USER = Youremail@mail.com

EMAIL_HOST_PASSWORD = your email account password.

Feel free to customize this template to match your application's design and functionality.
