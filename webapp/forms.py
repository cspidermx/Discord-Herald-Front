from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, HiddenField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, StopValidation, URL
from webapp.models import User


class AddEditRule(FlaskForm):
    ruleid = HiddenField('id')
    twitterhandle = StringField(label='When user @', validators=[DataRequired()],
                                description="Write the full twitter handle this rule will listen to. "
                                            "(Do not include the '@')")
    lookfor = StringField(label='Tweets any of this keywords', validators=[DataRequired()],
                          description="Write any number of keywords, separated by comas (This is case sensitive).")
    hook = StringField(label='Use this Webhook', validators=[DataRequired(), URL()],
                       description="Copy-Paste the full Discord webhook URL.")
    submit = SubmitField('Send')


class LoginForm(FlaskForm):
    username = StringField('Username')  # , validators=[DataRequired()])
    password = PasswordField('Password')  # , validators=[DataRequired()])
    remember_me = BooleanField('Remember me')
    submit1 = SubmitField('Login')
    submit2 = SubmitField('Signup')

    def validate(self):
        if not super().validate():
            return False
        if self.username.data is None or str(self.username.data).strip() == '':
            self.username.errors.append('Username is required.')
            return False
        if self.password.data is None or str(self.password.data).strip() == '':
            self.password.errors.append('Password is required.')
            return False
        return True


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Username is not available.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('This email address is already in use.')


class EditProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    # oldpassword = PasswordField('Previous Password')
    newpassword = PasswordField('New Password')
    newpassword2 = PasswordField('Repeat New Password', validators=[EqualTo('newpassword')])
    submit = SubmitField('Send')

    def __init__(self, original_username, original_email, *args, **kwargs):
        super(EditProfileForm, self).__init__(*args, **kwargs)
        self.original_username = original_username
        self.username.data = original_username
        self.original_email = original_email
        self.email.data = original_email

    def validate_username(self, username):
        if username.data != self.original_username:
            user = User.query.filter_by(username=username.data).first()
            if user is not None:
                raise ValidationError('Username is not available.')

    def validate_email(self, email):
        if email.data != self.original_email:
            user = User.query.filter_by(email=email.data).first()
            if user is not None:
                raise ValidationError('This email address is already in use.')

    ''' def validate_oldpassword(self, pwd):
        if self.newpassword.data != "":
            user = User.query.filter_by(username=self.username.id).first()
            if user is None:
                raise ValidationError('Unknown user.')
            else:
                if not user.check_password(pwd.data):
                    raise ValidationError('Incorrect Old Password.')            '''

    def validate_olduser(self):
        if self.newpassword.data != "":
            user = User.query.filter_by(username=self.username.id).first()
            if user is None:
                raise ValidationError('Unknown user.')


class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Reset Password')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('Email address not found.')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Request Password Reset')
