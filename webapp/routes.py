import os
from flask import render_template, flash, redirect, url_for, request
from webapp import app
from webapp.forms import LoginForm
from flask_login import current_user, login_user
from webapp.models import User, Rules, Service, Since
from flask_login import logout_user
from flask_login import login_required
from flask import request
from werkzeug.urls import url_parse
from webapp import wappdb
from webapp.forms import RegistrationForm, EditProfileForm, ResetPasswordRequestForm, ResetPasswordForm, AddEditRule
from email.message import EmailMessage
import threading
import smtplib
from Crypto.Cipher import AES
import random
import string
from flask import send_from_directory


def id_generator(txt):
        def rnddigits(size=6, chars=string.ascii_uppercase + string.digits):
            return ''.join(random.choice(chars) for _ in range(size))
        atras = random.randint(1, 9)
        adelante = random.randint(1, 9)
        return str(atras) + rnddigits(size=adelante) + txt + rnddigits(size=atras) + str(adelante)


def id_unscrambler(txt):
    atras = (int(txt[0]) + 1) * -1
    adelante = int(txt[-1]) + 1
    return txt[adelante:atras]


def lock(set_as):
    in_use = True
    s = None
    while in_use:
        in_use = False
        s = Service.query.first()
        if s is not None:
            if set_as:
                in_use = s.in_use
    if s is not None:
        s.in_use = in_use
        wappdb.session.commit()
    else:
        s = Service(id=1, stopped=False, in_use=in_use)
        wappdb.session.add(s)
        print(wappdb.session.commit())


def send_async_email(app_, srv, msge):
    with app_.app_context():
        if not srv['SSL']:
            smtp = smtplib.SMTP(srv['server'], srv['port'])
            smtp.starttls()
        else:
            smtp = smtplib.SMTP_SSL(srv['server'], srv['port'])  # Use this for Nemaris Server
        smtp.login(srv['user'], srv['password'])
        smtp.sendmail(msge['From'], msge['To'], msge.as_string())
        smtp.quit()


def send_email(server, msg):
    threading.Thread(target=send_async_email, args=(app, server, msg)).start()


def send_password_reset_email(usr):
    smtpserver = app.config['SMTP']

    msg = EmailMessage()
    msg['Subject'] = "Restablecer Password - Robot Email"
    msg['From'] = smtpserver['user']
    msg['To'] = usr.email
    msg.set_type('text/html')

    token = usr.get_reset_password_token()
    msg.set_content(render_template('email/reset_password.txt', user=usr, token=token))
    html_msg = render_template('email/reset_password.html', user=usr, token=token)
    msg.add_alternative(html_msg, subtype="html")

    send_email(smtpserver, msg)


def decrypt_id(ctxt):
    # ctxt = request.values.get('deledit_rule').encode("ISO-8859-1")
    decryption_suite = AES.new(app.config['SECRET_KEY'].encode("ISO-8859-1"), AES.MODE_CBC,
                               iv=app.config['SECRET_IV'].encode("ISO-8859-1"))
    ptext = decryption_suite.decrypt(ctxt).decode("utf-8").strip()
    return ptext


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')


@app.route('/', defaults={'editid': None}, methods=['GET', 'POST'])
@app.route('/<editid>', methods=['GET', 'POST'])
@app.route('/index', defaults={'editid': None}, methods=['GET', 'POST'])
@app.route('/index/<editid>', methods=['GET', 'POST'])
@login_required
def index(editid):
    frmss = AddEditRule()
    rls = Rules.query.filter_by(id_user=current_user.id)
    if editid is not None and not frmss.submit.data:
        if editid != "#" and editid != 'favicon.ico':
            ruletoedit = Rules.query.filter_by(id=int(id_unscrambler(editid))).first()
            frmss.ruleid.data = ruletoedit.enc_id()
            frmss.twitterhandle.data = ruletoedit.handle
            frmss.lookfor.data = ruletoedit.lookfor
            frmss.hook.data = ruletoedit.discrobot
    if frmss.validate_on_submit():
        if frmss.ruleid.data == "":
            newrule = Rules(id_user=current_user.id,
                            handle=str(frmss.twitterhandle.data).replace('@', '').strip(),
                            lookfor=frmss.lookfor.data.strip(),
                            discrobot=frmss.hook.data.strip())
            newrule.new_id()
            lock(True)
            wappdb.session.add(newrule)
            print(wappdb.session.commit())
            lock(False)
            flash('New RULE has been saved.')
        else:
            cipher_text = frmss.ruleid.data.encode("ISO-8859-1")
            plain_text = decrypt_id(cipher_text)
            lock(True)
            ruletoedit = Rules.query.filter_by(id=int(plain_text)).first()
            ruletoedit.handle = str(frmss.twitterhandle.data).replace('@', '')
            ruletoedit.lookfor = frmss.lookfor.data.strip()
            ruletoedit.discrobot = frmss.hook.data.strip()
            print(wappdb.session.commit())
            lock(False)
        return redirect(url_for('index'))
    return render_template('index.html', title='Discord Herald Home', form=frmss, rs=rls)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    frm_lgin = LoginForm()
    if frm_lgin.submit1.data:
        if frm_lgin.validate_on_submit():
            user = User.query.filter_by(username=frm_lgin.username.data).first()
            if user is None or not user.check_password(frm_lgin.password.data):
                flash('Invalid Username or Password')
                return redirect(url_for('login'))
            login_user(user, remember=frm_lgin.remember_me.data)
            next_page = request.args.get('next')
            if not next_page or url_parse(next_page).netloc != '':
                next_page = url_for('index')
            return redirect(next_page)
    elif frm_lgin.submit2.data:
        return redirect(url_for('register'))
    return render_template('login.html', title='Discord Herald Login', form=frm_lgin)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data,
                    email=form.email.data)
        user.set_password(form.password.data)
        user.new_id()
        wappdb.session.add(user)
        print(wappdb.session.commit())
        flash('New user has been registered.')
        login_user(user, remember=False)
        return redirect(url_for('index'))
    return render_template('register.html', title='Discord Herald Registration', form=form)


@app.route('/usuarios')
@login_required
def usuarios():
    if current_user.level == 0:
        u = User.query.order_by(User.level, User.username).all()
        return render_template('usuarios.html', title='Usuarios', users=u)
    else:
        return redirect(url_for('index'))


@app.route('/perfil/<username>', methods=['GET', 'POST'])
@app.route('/perfil', defaults={'username': None}, methods=['GET', 'POST'])
@app.route('/perfil/', defaults={'username': None}, methods=['GET', 'POST'])
@login_required
def perfil(username):
    username = id_unscrambler(username)
    if username != current_user.id and current_user.level != 0:
        return redirect(url_for('index'))
    usr = User.query.filter_by(id=username).first_or_404()
    frm = EditProfileForm(usr.username, usr.email)
    frm.username.id = usr.username
    frm.email.id = usr.email
    if frm.validate_on_submit():
        user = User.query.filter_by(username=frm.original_username).first()
        user.username = frm.username.data
        user.email = frm.email.data
        # if frm.oldpassword != "":
        user.set_password(frm.newpassword.data)
        wappdb.session.commit()
        flash('Actualización completada con éxito.')
        return redirect(url_for('usuarios'))
    return render_template('perfil.html', user=usr, form=frm)


@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
        flash('Check your email for the instructions to reset your password')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html', title='Discord Herald Reset Password', form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        wappdb.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)


@app.route('/editrule', methods=['GET', 'POST'])
@login_required
def editrule():
    if request.method == 'POST':
        cipher_text = request.values.get('deledit_rule').encode("ISO-8859-1")
        plain_text = decrypt_id(cipher_text)
        return redirect(url_for('index') + '/' + id_generator(plain_text))
    return redirect(url_for('index'))


@app.route('/deleterule', methods=['GET', 'POST'])
@login_required
def deleterule():
    if request.method == 'POST':
        cipher_text = request.values.get('deledit_rule').encode("ISO-8859-1")
        plain_text = decrypt_id(cipher_text)
        # print("Cifrado Delete: {} - Plain Delete: {}".format(cipher_text, plain_text))
        r = Rules.query.filter_by(id=int(plain_text)).first()
        lock(True)
        wappdb.session.delete(r)
        wappdb.session.commit()
        lock(False)
    return redirect(url_for('index'))


@app.route('/dltusr/<iduser>', methods=['GET', 'POST'])
@app.route('/dltusr', defaults={'iduser': None}, methods=['GET', 'POST'])
@app.route('/dltusr/', defaults={'iduser': None}, methods=['GET', 'POST'])
@login_required
def dltusr(iduser):
    cipher_text = iduser.encode("ISO-8859-1")
    iduser = decrypt_id(cipher_text)
    if current_user.level != 0:
        return redirect(url_for('index'))
    usr = User.query.filter_by(id=iduser).first()
    lock(True)
    if usr is not None:
        rls = Rules.query.filter_by(id=iduser).all()
        if len(rls) != 0:
            for r in rls:
                since = Since.query.filter_by(rule_id=r.id).all()
                if len(since) != 0:
                    for s in since:
                        wappdb.session.delete(s)
                    wappdb.session.commit()
                wappdb.session.delete(r)
            wappdb.session.commit()
        wappdb.session.delete(usr)
        wappdb.session.commit()
    lock(False)
    return redirect(url_for('usuarios'))
