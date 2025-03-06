from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file, Response
import flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user, AnonymousUserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import whois
import socket
import re
import dns.resolver
import time
import json
from functools import wraps
import platform

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///domains.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Site ayarları tablosu
class SiteSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    site_name = db.Column(db.String(100), default="Alan Adı Takip Sistemi")
    maintenance_mode = db.Column(db.Boolean, default=False)
    maintenance_message = db.Column(db.Text, default="Site şu anda bakım modundadır. Lütfen daha sonra tekrar deneyin.")
    contact_email = db.Column(db.String(100), default="admin@example.com")
    footer_text = db.Column(db.String(255), default=" 2025 Alan Adı Takip Sistemi")
    items_per_page = db.Column(db.Integer, default=10)
    max_whois_cache_days = db.Column(db.Integer, default=7)
    allow_registration = db.Column(db.Boolean, default=True)
    email_confirmation_required = db.Column(db.Boolean, default=False)
    last_updated = db.Column(db.DateTime, default=datetime.now())
    
    @classmethod
    def get_settings(cls):
        settings = cls.query.first()
        if not settings:
            settings = cls()
            db.session.add(settings)
            db.session.commit()
        return settings

# Kullanıcı tablosu - admin rolü eklenmiş
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now())
    last_login = db.Column(db.DateTime)
    is_admin = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False)
    ban_reason = db.Column(db.Text)
    domains = db.relationship('Domain', backref='user', lazy=True)
    
    def __repr__(self):
        return f'<User {self.username}>'

# Alan adı tablosu (Güncellenmiş)
class Domain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain_name = db.Column(db.String(100), nullable=False)
    registrar = db.Column(db.String(100))
    registration_date = db.Column(db.DateTime)
    expiry_date = db.Column(db.DateTime)
    status = db.Column(db.String(50))
    nameservers = db.Column(db.String(500))  # Stored as comma-separated string
    registrant_name = db.Column(db.String(100))
    registrant_organization = db.Column(db.String(100))
    registrant_email = db.Column(db.String(100))
    tech_name = db.Column(db.String(100))
    tech_organization = db.Column(db.String(100))
    tech_email = db.Column(db.String(100))
    dns_a = db.Column(db.String(500))  # IP addresses
    dns_mx = db.Column(db.String(500))  # Mail servers
    dns_txt = db.Column(db.String(1000))  # TXT records
    cname_records = db.Column(db.String(500))  # CNAME records
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now())
    updated_at = db.Column(db.DateTime, default=datetime.now(), onupdate=datetime.now())
    whois_data = db.Column(db.Text)  # WHOIS verileri için alan eklendi
    
    @property
    def remaining_days(self):
        if not self.expiry_date:
            return None
        today = datetime.now().date()
        expiry = self.expiry_date.date() if isinstance(self.expiry_date, datetime) else self.expiry_date
        return (expiry - today).days
    
    def get_nameservers_list(self):
        if not self.nameservers:
            return []
        return [ns.strip() for ns in self.nameservers.split(',') if ns.strip()]
    
    def __repr__(self):
        return f'<Domain {self.domain_name}>'

# Kullanıcı yükleme işlevi
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Admin gerektiren rotalar için dekoratör
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Bu sayfaya erişim izniniz yok.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Bakım modu kontrolü için dekoratör
def check_maintenance_mode():
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            settings = SiteSettings.get_settings()
            # Sadece admin olmayan kullanıcılar için bakım sayfasına yönlendirme
            if settings.maintenance_mode and not (current_user.is_authenticated and current_user.is_admin):
                return redirect(url_for('maintenance'))
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

@app.before_request
def before_request():
    if current_user.is_authenticated and request.endpoint != 'static':
        session.permanent = True
        app.permanent_session_lifetime = timedelta(hours=24)
    
    # Bakım modu kontrolü - en başta yapılması gereken kontrol   
    settings = SiteSettings.get_settings()
    
    # Admin kullanıcıları hiçbir zaman bakım moduna yönlendirilmemelidir
    if current_user.is_authenticated and current_user.is_admin:
        # Admin kullanıcılar her sayfaya erişebilir
        pass
    elif settings.maintenance_mode:
        # Bakım modunda iken sadece belirli sayfalara izin ver
        allowed_endpoints = ['maintenance', 'login', 'static', 'logout']
        
        # Endpoint yoksa veya izin verilen listeye dahil değilse bakım sayfasına yönlendir
        if not request.endpoint or request.endpoint not in allowed_endpoints:
            return redirect(url_for('maintenance'))
    
    # Banlı kullanıcı kontrolü
    if current_user.is_authenticated and current_user.is_banned:
        logout_user()
        flash('Hesabınız banlanmıştır. Lütfen yöneticiyle iletişime geçin.', 'danger')
        return redirect(url_for('login'))

# Bakım sayfası
@app.route('/maintenance')
def maintenance():
    settings = SiteSettings.get_settings()
    
    # Bakım modu kapalıysa ana sayfaya yönlendir
    if not settings.maintenance_mode:
        return redirect(url_for('index'))
    
    # Admin kullanıcılar için özel mesaj göster
    is_admin = current_user.is_authenticated and current_user.is_admin
    
    # Admin kullanıcıları bakım sayfasında özel bildirim alırlar
    return render_template('maintenance.html', settings=settings, is_admin=is_admin)

# Ana sayfa
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# Giriş sayfası - Ban durumu kontrolü eklendi
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Oturum açmış kullanıcıyı kontrol et
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        # Kullanıcıyı doğrula
        if user and check_password_hash(user.password, password):
            # Ban durumunu kontrol et
            if user.is_banned:
                flash(f'Hesabınız banlanmıştır. Sebep: {user.ban_reason}', 'danger')
                return redirect(url_for('login'))
                
            login_user(user)
            user.last_login = datetime.now()
            db.session.commit()
            
            # Bakım modu kontrolü
            settings = SiteSettings.get_settings()
            
            # Admin veya normal kullanıcı sayfasına yönlendir
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            elif settings.maintenance_mode:
                # Normal kullanıcı ve bakım modu aktif ise bakım sayfasına yönlendir
                return redirect(url_for('maintenance'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash('Geçersiz kullanıcı adı veya şifre!', 'danger')
    
    return render_template('login.html')

# Kayıt sayfası
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Şifreler eşleşmiyor!', 'danger')
            return redirect(url_for('register'))
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Bu kullanıcı adı zaten kullanılıyor.', 'danger')
            return redirect(url_for('register'))
        
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('Bu e-posta adresi zaten kullanılıyor.', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Kayıt başarılı! Şimdi giriş yapabilirsiniz.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# Çıkış sayfası
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Panel sayfası
@app.route('/dashboard')
@login_required
def dashboard():
    settings = SiteSettings.get_settings()
    
    # Filtreleme ve sıralama parametrelerini al
    sort_by = request.args.get('sort_by', 'created_at')
    registrar_filter = request.args.get('registrar', '')
    status_filter = request.args.get('status', '')
    
    # Alan adlarını sorgula
    query = Domain.query.filter_by(user_id=current_user.id)
    
    # Kayıt firması filtresi
    if registrar_filter:
        if registrar_filter == 'empty':
            # Boş veya null kayıt firmaları için özel filtre
            query = query.filter(or_(Domain.registrar == None, Domain.registrar == ''))
        else:
            query = query.filter(Domain.registrar == registrar_filter)
    
    # Durum filtresi
    if status_filter:
        if status_filter == 'empty':
            # Boş veya null statüs değerleri için özel filtre
            query = query.filter(or_(Domain.status == None, Domain.status == ''))
        else:
            query = query.filter(Domain.status == status_filter)
    
    # Sıralama
    if sort_by == 'domain_name':
        query = query.order_by(Domain.domain_name)
    elif sort_by == 'registrar':
        query = query.order_by(Domain.registrar.nullsfirst())  # Null değerler önce
    elif sort_by == 'expiry_date':
        query = query.order_by(Domain.expiry_date.nullsfirst())  # Null değerler önce
    else:  # default: created_at
        query = query.order_by(Domain.created_at.desc())
    
    # Sonuçları al
    domains = query.all()
    
    # Kayıt firmalarının listesini çekelim (filtreleme için)
    registrars = db.session.query(Domain.registrar.distinct()).filter(
        Domain.user_id == current_user.id,
        Domain.registrar.isnot(None),
        Domain.registrar != ''
    ).all()
    registrars = [r[0] for r in registrars if r[0]]  # None ve boş değerleri filtrele
    registrars.sort()  # Alfabetik sırala
    
    # Statü değerlerinin listesini çekelim (filtreleme için)
    statuses = db.session.query(Domain.status.distinct()).filter(
        Domain.user_id == current_user.id,
        Domain.status.isnot(None),
        Domain.status != ''
    ).all()
    statuses = [s[0] for s in statuses if s[0]]  # None ve boş değerleri filtrele
    statuses.sort()  # Alfabetik sırala
    
    # Boş kayıt firması ve statü değerleri var mı kontrol et
    empty_registrars_exist = db.session.query(Domain).filter(
        Domain.user_id == current_user.id,
        or_(Domain.registrar == None, Domain.registrar == '')
    ).first() is not None
    
    empty_statuses_exist = db.session.query(Domain).filter(
        Domain.user_id == current_user.id,
        or_(Domain.status == None, Domain.status == '')
    ).first() is not None
    
    # Debug için
    print(f"Sıralama: {sort_by}, Kayıt Firması: {registrar_filter}, Durum: {status_filter}")
    print(f"Bulunan alan adı sayısı: {len(domains)}")
    print(f"Kayıt firmaları: {registrars}")
    print(f"Statü değerleri: {statuses}")
    
    return render_template(
        'dashboard.html', 
        domains=domains, 
        settings=settings,
        sort_by=sort_by,
        registrar_filter=registrar_filter,
        status_filter=status_filter,
        registrars=registrars,
        statuses=statuses,
        empty_registrars_exist=empty_registrars_exist,
        empty_statuses_exist=empty_statuses_exist
    )

# Alan adı ekleme sayfası
@app.route('/add_domain', methods=['GET', 'POST'])
@login_required
def add_domain():
    if request.method == 'POST':
        domain_name = request.form.get('domain_name')
        
        if not domain_name:
            flash('Alan adı boş olamaz!', 'danger')
            return redirect(url_for('add_domain'))
        
        # Check if domain already exists for this user
        existing_domain = Domain.query.filter_by(domain_name=domain_name, user_id=current_user.id).first()
        if existing_domain:
            flash('Bu alan adı zaten listenizde bulunuyor!', 'danger')
            return redirect(url_for('dashboard'))
        
        # Get domain information
        domain_info = get_domain_info(domain_name)
        
        new_domain = Domain(
            domain_name=domain_name,
            registrar=domain_info['registrar'],
            registration_date=domain_info['registration_date'],
            expiry_date=domain_info['expiry_date'],
            status=domain_info['status'],
            nameservers=','.join(domain_info['nameservers']),
            registrant_name=domain_info['registrant_name'],
            registrant_organization=domain_info['registrant_organization'],
            registrant_email=domain_info['registrant_email'],
            tech_name=domain_info['tech_name'],
            tech_organization=domain_info['tech_organization'],
            tech_email=domain_info['tech_email'],
            dns_a=','.join(domain_info['dns_records']['A']),
            dns_mx=','.join(domain_info['dns_records']['MX']),
            dns_txt=','.join(domain_info['dns_records']['TXT']),
            cname_records=','.join(domain_info['dns_records'].get('CNAME', [])),
            user_id=current_user.id
        )
        
        db.session.add(new_domain)
        db.session.commit()
        
        flash('Alan adı başarıyla eklendi!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('add_domain.html')

# Toplu alan adı ekleme sayfası
@app.route('/bulk_add_domain', methods=['GET', 'POST'])
@login_required
def bulk_add_domain():
    if request.method == 'POST':
        # This is only used when the form is manually submitted without JavaScript
        # JavaScript handling is preferred for better UX
        domain_list = request.form.get('domain_list', '')
        domains = [d.strip() for d in domain_list.split('\n') if d.strip()]
        
        success_count = 0
        error_count = 0
        
        for domain_name in domains:
            # Check if domain already exists for this user
            existing_domain = Domain.query.filter_by(domain_name=domain_name, user_id=current_user.id).first()
            if existing_domain:
                error_count += 1
                continue
            
            try:
                # Get domain information with error handling
                domain_info = get_domain_info(domain_name)
                
                new_domain = Domain(
                    domain_name=domain_name,
                    registrar=domain_info['registrar'],
                    registration_date=domain_info['registration_date'],
                    expiry_date=domain_info['expiry_date'],
                    status=domain_info['status'],
                    nameservers=','.join(domain_info['nameservers']),
                    registrant_name=domain_info['registrant_name'],
                    registrant_organization=domain_info['registrant_organization'],
                    registrant_email=domain_info['registrant_email'],
                    tech_name=domain_info['tech_name'],
                    tech_organization=domain_info['tech_organization'],
                    tech_email=domain_info['tech_email'],
                    dns_a=','.join(domain_info['dns_records']['A']),
                    dns_mx=','.join(domain_info['dns_records']['MX']),
                    dns_txt=','.join(domain_info['dns_records']['TXT']),
                    cname_records=','.join(domain_info['dns_records'].get('CNAME', [])),
                    user_id=current_user.id
                )
                
                db.session.add(new_domain)
                db.session.commit()
                success_count += 1
            except Exception as e:
                error_count += 1
                print(f"Error adding domain {domain_name}: {e}")
        
        if success_count > 0:
            flash(f'{success_count} alan adı başarıyla eklendi!', 'success')
        if error_count > 0:
            flash(f'{error_count} alan adı eklenirken hata oluştu!', 'warning')
        
        return redirect(url_for('dashboard'))
    
    return render_template('bulk_add_domain.html')

# Alan adı detay sayfası
@app.route('/domain/<int:domain_id>')
@login_required
def domain_detail(domain_id):
    domain = db.session.get(Domain, domain_id)
    
    # Check if the domain belongs to the current user
    if domain.user_id != current_user.id:
        flash('Bu işlem için yetkiniz yok!', 'danger')
        return redirect(url_for('dashboard'))
    
    return render_template('domain_detail.html', domain=domain)

# Alan adı yenileme sayfası
@app.route('/refresh_domain/<int:domain_id>', methods=['GET'])
def refresh_domain(domain_id):
    # Domain'i bul
    domain = Domain.query.get_or_404(domain_id)
    
    # Kullanıcının kendi domain'i mi kontrol et
    if domain.user_id != current_user.id and not current_user.is_admin:
        flash('Bu işlem için yetkiniz yok.', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        # Alan adı bilgilerini güncelle
        domain_info = get_domain_info(domain.domain_name)
        
        if domain_info:
            # Modeli güncelle
            domain.registrar = domain_info.get('registrar')
            domain.registration_date = domain_info.get('creation_date')
            domain.expiry_date = domain_info.get('expiration_date')
            domain.status = domain_info.get('status')
            domain.nameservers = ','.join(domain_info.get('nameservers', []))
            domain.registrant_name = domain_info.get('registrant_name')
            domain.registrant_organization = domain_info.get('registrant_organization')
            domain.registrant_email = domain_info.get('registrant_email')
            domain.whois_data = domain_info.get('whois_data')
            domain.updated_at = datetime.now()
            
            # DNS bilgilerini güncelle
            dns_records = get_dns_records(domain.domain_name)
            domain.dns_a = ','.join(dns_records.get('A', []))
            domain.dns_mx = ','.join(dns_records.get('MX', []))
            domain.dns_txt = ','.join(dns_records.get('TXT', []))
            domain.cname_records = ','.join(dns_records.get('CNAME', []))
            
            db.session.commit()
            flash('Alan adı bilgileri güncellendi.', 'success')
        else:
            flash('Alan adı bilgileri güncellenemedi.', 'danger')
    
    except Exception as e:
        flash(f'Hata oluştu: {str(e)}', 'danger')
    
    return redirect(url_for('dashboard'))

# Alan adı düzenleme sayfası
@app.route('/update_domain/<int:domain_id>', methods=['GET', 'POST'])
@login_required
def update_domain(domain_id):
    domain = db.session.get(Domain, domain_id)
    
    # Check if the domain belongs to the current user
    if domain.user_id != current_user.id:
        flash('Bu işlem için yetkiniz yok!', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        registrar = request.form.get('registrar')
        
        # Update only the registrar
        domain.registrar = registrar
        
        # Get updated domain information from whois
        domain_info = get_domain_info(domain.domain_name)
        domain.expiry_date = domain_info['expiry_date']
        domain.status = domain_info['status']
        domain.nameservers = ','.join(domain_info['nameservers'])
        domain.registrant_name = domain_info['registrant_name']
        domain.registrant_organization = domain_info['registrant_organization']
        domain.registrant_email = domain_info['registrant_email']
        domain.tech_name = domain_info['tech_name']
        domain.tech_organization = domain_info['tech_organization']
        domain.tech_email = domain_info['tech_email']
        domain.dns_a = ','.join(domain_info['dns_records']['A'])
        domain.dns_mx = ','.join(domain_info['dns_records']['MX'])
        domain.dns_txt = ','.join(domain_info['dns_records']['TXT'])
        domain.cname_records = ','.join(domain_info['dns_records'].get('CNAME', []))
        
        db.session.commit()
        
        flash('Alan adı bilgileri güncellendi!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('update_domain.html', domain=domain)

# Alan adı silme sayfası
@app.route('/delete_domain/<int:domain_id>')
@login_required
def delete_domain(domain_id):
    domain = db.session.get(Domain, domain_id)
    
    # Check if the domain belongs to the current user
    if domain.user_id != current_user.id:
        flash('Bu işlem için yetkiniz yok!', 'danger')
        return redirect(url_for('dashboard'))
    
    db.session.delete(domain)
    db.session.commit()
    
    flash('Alan adı silindi!', 'success')
    return redirect(url_for('dashboard'))

# Alan adı API endpoint
@app.route('/add_domain_api', methods=['POST'])
@login_required
def add_domain_api():
    data = request.get_json()
    domain_name = data.get('domain_name', '').strip()
    
    if not domain_name:
        return jsonify({
            'success': False,
            'message': 'Alan adı boş olamaz!'
        })
    
    # Validate and clean domain
    is_valid, result = validate_domain(domain_name)
    if not is_valid:
        return jsonify({
            'success': False,
            'message': f'Geçersiz alan adı formatı: {result}'
        })
    
    # Use cleaned domain name
    domain_name = result
    
    # Check if domain already exists for this user
    existing_domain = Domain.query.filter_by(domain_name=domain_name, user_id=current_user.id).first()
    if existing_domain:
        return jsonify({
            'success': False,
            'message': 'Bu alan adı zaten listenizde bulunuyor!'
        })
    
    try:
        # Get domain information - use a timeout to prevent hanging on problematic domains
        start_time = time.time()
        domain_info = get_domain_info(domain_name)
        
        # If processing took too long, log a warning
        processing_time = time.time() - start_time
        if processing_time > 5:
            print(f"Warning: Domain processing for {domain_name} took {processing_time:.2f} seconds")
        
        # Check for error status
        if domain_info['status'] and domain_info['status'].startswith('Hata:'):
            return jsonify({
                'success': False,
                'message': domain_info['status']
            })
        
        new_domain = Domain(
            domain_name=domain_name,
            registrar=domain_info['registrar'],
            registration_date=domain_info['registration_date'],
            expiry_date=domain_info['expiry_date'],
            status=domain_info['status'],
            nameservers=','.join(domain_info['nameservers']),
            registrant_name=domain_info['registrant_name'],
            registrant_organization=domain_info['registrant_organization'],
            registrant_email=domain_info['registrant_email'],
            tech_name=domain_info['tech_name'],
            tech_organization=domain_info['tech_organization'],
            tech_email=domain_info['tech_email'],
            dns_a=','.join(domain_info['dns_records']['A']),
            dns_mx=','.join(domain_info['dns_records']['MX']),
            dns_txt=','.join(domain_info['dns_records']['TXT']),
            cname_records=','.join(domain_info['dns_records'].get('CNAME', [])),
            user_id=current_user.id
        )
        
        db.session.add(new_domain)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f"Alan adı başarıyla eklendi! ({domain_info['status']})"
        })
    except Exception as e:
        db.session.rollback()  # Rollback any failed transaction
        error_message = str(e)
        print(f"Error adding domain {domain_name}: {error_message}")
        
        # Provide a more user-friendly error message
        if "timeout" in error_message.lower() or "timed out" in error_message.lower():
            friendly_message = "İşlem zaman aşımına uğradı. Sunucu meşgul olabilir veya domain geçersiz olabilir."
        elif "connection" in error_message.lower():
            friendly_message = "Bağlantı hatası. Lütfen internet bağlantınızı kontrol edin."
        else:
            friendly_message = "İşlem sırasında bir hata oluştu."
        
        return jsonify({
            'success': False,
            'message': f"{friendly_message} (Hata: {error_message[:100]}...)"
        })

# Alan adı doğrulama işlevi
def validate_domain(domain_name):
    """Validates if the input is a properly formatted domain name."""
    if not domain_name or not isinstance(domain_name, str):
        return False, "Alan adı boş veya geçersiz format"
        
    # Remove http://, https://, www. prefixes
    cleaned_domain = domain_name.lower()
    for prefix in ['http://', 'https://', 'www.']:
        if cleaned_domain.startswith(prefix):
            cleaned_domain = cleaned_domain[len(prefix):]
    
    # Remove any paths or query parameters
    cleaned_domain = cleaned_domain.split('/')[0].split('?')[0].split('#')[0]
    
    # Basic domain format validation
    domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    if not re.match(domain_pattern, cleaned_domain):
        return False, "Geçersiz domain formatı"
    
    return True, cleaned_domain

# Alan adı bilgilerini getirme işlevi
def get_domain_info(domain_name):
    try:
        # Input validation
        is_valid, result = validate_domain(domain_name)
        if not is_valid:
            return {
                'registrar': "Bilinmiyor",
                'registration_date': None,
                'expiry_date': None,
                'status': f"Hata: {result}",
                'nameservers': [],
                'registrant_name': None,
                'registrant_organization': None,
                'registrant_email': None,
                'tech_name': None,
                'tech_organization': None,
                'tech_email': None,
                'dns_records': {'A': [], 'MX': [], 'TXT': [], 'NS': []}
            }
        
        # Use validated and cleaned domain name
        domain_name = result
            
        # First check if domain is registered
        try:
            is_available, availability_message = check_domain_availability(domain_name)
            if is_available:
                return {
                    'registrar': None,
                    'registration_date': None,
                    'expiry_date': None,
                    'status': "Boşta",
                    'nameservers': [],
                    'registrant_name': None,
                    'registrant_organization': None,
                    'registrant_email': None,
                    'tech_name': None,
                    'tech_organization': None,
                    'tech_email': None,
                    'dns_records': {'A': [], 'MX': [], 'TXT': [], 'NS': []}
                }
        except Exception as e:
            print(f"Error checking domain availability: {e}")
            # Continue with whois lookup even if availability check fails

        try:
            domain_info = whois.whois(domain_name)
            
            # Validate WHOIS response - sometimes returns empty data for invalid domains
            if domain_info.domain_name is None and not domain_info.registrar and not domain_info.registrant:
                return {
                    'registrar': "Bilinmiyor",
                    'registration_date': None,
                    'expiry_date': None,
                    'status': "Hata: Geçersiz WHOIS cevabı",
                    'nameservers': [],
                    'registrant_name': None,
                    'registrant_organization': None,
                    'registrant_email': None,
                    'tech_name': None,
                    'tech_organization': None,
                    'tech_email': None,
                    'dns_records': {'A': [], 'MX': [], 'TXT': [], 'NS': []}
                }
        except Exception as e:
            print(f"Whois lookup failed for {domain_name}: {e}")
            return {
                'registrar': "Bilinmiyor",
                'registration_date': None,
                'expiry_date': None,
                'status': "Hata: Whois bilgisi alınamadı",
                'nameservers': [],
                'registrant_name': None,
                'registrant_organization': None,
                'registrant_email': None,
                'tech_name': None,
                'tech_organization': None,
                'tech_email': None,
                'dns_records': {'A': [], 'MX': [], 'TXT': [], 'NS': []}
            }
            
        try:
            dns_records = get_dns_records(domain_name)
        except Exception as e:
            print(f"DNS lookup failed for {domain_name}: {e}")
            dns_records = {'A': [], 'MX': [], 'TXT': [], 'NS': []}
        
        # Handle different date formats and multiple dates
        expiry_date = None
        try:
            if domain_info.expiration_date:
                if isinstance(domain_info.expiration_date, list):
                    expiry_date = domain_info.expiration_date[0]
                else:
                    expiry_date = domain_info.expiration_date
        except Exception as e:
            print(f"Error processing expiry date for {domain_name}: {e}")

        # Handle registration date
        registration_date = None
        try:
            if domain_info.creation_date:
                if isinstance(domain_info.creation_date, list):
                    registration_date = domain_info.creation_date[0]
                else:
                    registration_date = domain_info.creation_date
        except Exception as e:
            print(f"Error processing registration date for {domain_name}: {e}")
        
        # Handle domain name normalization - sometimes whois returns it with uppercase or variations
        try:
            if domain_info.domain_name:
                if isinstance(domain_info.domain_name, list):
                    whois_domain = domain_info.domain_name[0].lower()
                else:
                    whois_domain = domain_info.domain_name.lower()
                    
                # If the whois domain doesn't match our input (ignoring www. and case)
                cleaned_input = domain_name.lower().replace('www.', '')
                cleaned_whois = whois_domain.lower().replace('www.', '')
                
                if cleaned_input != cleaned_whois and not cleaned_input.endswith('.' + cleaned_whois):
                    print(f"Warning: WHOIS domain {whois_domain} doesn't match input {domain_name}")
        except Exception as e:
            print(f"Error comparing domain names for {domain_name}: {e}")
        
        # Handle nameservers
        nameservers = []
        try:
            if domain_info.name_servers:
                if isinstance(domain_info.name_servers, list):
                    nameservers = [ns.lower() for ns in domain_info.name_servers if ns]
                else:
                    nameservers = [domain_info.name_servers.lower()]
        except Exception as e:
            print(f"Error processing nameservers for {domain_name}: {e}")

        # Safely get registrar
        try:
            registrar = domain_info.registrar if domain_info.registrar else "Bilinmiyor"
        except Exception:
            registrar = "Bilinmiyor"
            
        # Determine status
        try:
            if expiry_date:
                if expiry_date > datetime.now():
                    status = "Active"
                else:
                    status = "Expired"
            else:
                # If we have nameservers or A records but no expiry date
                if nameservers or dns_records['A']:
                    status = "Active (Tarih Bilinmiyor)"
                else:
                    status = "Bilinmiyor"
        except Exception:
            status = "Bilinmiyor"
        
        # Safely get other fields
        try:
            registrant_name = domain_info.get('registrant_name')
        except Exception:
            registrant_name = None
            
        try:
            registrant_organization = domain_info.get('org')
        except Exception:
            registrant_organization = None
            
        try:
            registrant_email = domain_info.get('registrant_email')
        except Exception:
            registrant_email = None
            
        try:
            tech_name = domain_info.get('tech_name')
        except Exception:
            tech_name = None
            
        try:
            tech_organization = domain_info.get('tech_organization')
        except Exception:
            tech_organization = None
            
        try:
            tech_email = domain_info.get('tech_email')
        except Exception:
            tech_email = None
        
        return {
            'registrar': registrar,
            'registration_date': registration_date,
            'expiry_date': expiry_date,
            'status': status,
            'nameservers': nameservers,
            'registrant_name': registrant_name,
            'registrant_organization': registrant_organization,
            'registrant_email': registrant_email,
            'tech_name': tech_name,
            'tech_organization': tech_organization,
            'tech_email': tech_email,
            'dns_records': dns_records
        }
    except Exception as e:
        print(f"Critical error getting domain info for {domain_name}: {e}")
        return {
            'registrar': "Bilinmiyor",
            'registration_date': None,
            'expiry_date': None,
            'status': "Hata: İşlem sırasında bir sorun oluştu",
            'nameservers': [],
            'registrant_name': None,
            'registrant_organization': None,
            'registrant_email': None,
            'tech_name': None,
            'tech_organization': None,
            'tech_email': None,
            'dns_records': {'A': [], 'MX': [], 'TXT': [], 'NS': []}
        }

# Alan adı durumunu kontrol etme işlevi
def check_domain_availability(domain_name):
    try:
        # Basic domain format validation
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if not re.match(domain_pattern, domain_name):
            return False, "Geçersiz domain formatı"
            
        # Check if domain resolves
        socket.gethostbyname(domain_name)
        return False, "Domain kayıtlı" # Domain is registered
    except socket.gaierror:
        try:
            # Double check with a WHOIS query
            w = whois.whois(domain_name)
            if w.domain_name is None:
                return True, "Domain boşta olabilir"
            else:
                return False, "Domain kayıtlı (WHOIS)"
        except Exception:
            return True, "Domain boşta olabilir"
    except Exception as e:
        return False, f"Kontrol hatası: {str(e)}"

# DNS kayıtlarını getirme işlevi
def get_dns_records(domain_name):
    records = {
        'A': [], 'MX': [], 'TXT': [], 'NS': []
    }
    
    try:
        # Use a custom resolver with timeout to prevent hanging
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        
        # Get A records
        try:
            a_records = resolver.resolve(domain_name, 'A')
            records['A'] = [str(r) for r in a_records]
        except Exception as e:
            print(f"A record lookup failed for {domain_name}: {e}")

        # Get MX records
        try:
            mx_records = resolver.resolve(domain_name, 'MX')
            records['MX'] = [str(r.exchange) for r in mx_records]
        except Exception as e:
            print(f"MX record lookup failed for {domain_name}: {e}")

        # Get TXT records
        try:
            txt_records = resolver.resolve(domain_name, 'TXT')
            records['TXT'] = [str(r) for r in txt_records]
        except Exception as e:
            print(f"TXT record lookup failed for {domain_name}: {e}")

        # Get NS records
        try:
            ns_records = resolver.resolve(domain_name, 'NS')
            records['NS'] = [str(r) for r in ns_records]
        except Exception as e:
            print(f"NS record lookup failed for {domain_name}: {e}")

    except Exception as e:
        print(f"Error getting DNS records for {domain_name}: {e}")

    return records

# ADMIN PANEL ROUTEs
# Admin ana sayfa
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    settings = SiteSettings.get_settings()
    
    # Kullanıcı ve domain sayıları
    user_count = User.query.count()
    domain_count = Domain.query.count()
    
    # Son kayıt olan kullanıcılar
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    
    # Son eklenen alan adları
    recent_domains = Domain.query.order_by(Domain.created_at.desc()).limit(5).all()
    
    # Domain ve kullanıcı istatistikleri için veri (son 7 gün)
    domain_stats_labels = []
    domain_stats_values = []
    user_stats_values = []
    
    end_date = datetime.now()
    start_date = end_date - timedelta(days=6)
    
    for i in range(7):
        day = start_date + timedelta(days=i)
        next_day = day + timedelta(days=1)
        
        # Tarih formatı
        date_label = day.strftime('%d %b')
        domain_stats_labels.append(date_label)
        
        # O gün eklenen alanları say
        day_domains = Domain.query.filter(
            Domain.created_at >= day,
            Domain.created_at < next_day
        ).count()
        domain_stats_values.append(day_domains)
        
        # O gün kayıt olan kullanıcıları say
        day_users = User.query.filter(
            User.created_at >= day,
            User.created_at < next_day
        ).count()
        user_stats_values.append(day_users)
    
    return render_template(
        'admin/dashboard.html', 
        settings=settings,
        user_count=user_count,
        domain_count=domain_count,
        recent_users=recent_users,
        recent_domains=recent_domains,
        domain_stats_labels=domain_stats_labels,
        domain_stats_values=domain_stats_values,
        user_stats_values=user_stats_values
    )

# Kullanıcı listesi
@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    settings = SiteSettings.get_settings()
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search', '')
    
    if search_query:
        users = User.query.filter(
            (User.username.ilike(f'%{search_query}%')) | 
            (User.email.ilike(f'%{search_query}%'))
        ).order_by(User.created_at.desc())
    else:
        users = User.query.order_by(User.created_at.desc())
    
    users = users.paginate(page=page, per_page=settings.items_per_page, error_out=False)
    
    return render_template('admin/users.html', users=users, settings=settings, search_query=search_query)

# Kullanıcı detayları
@app.route('/admin/users/<int:user_id>')
@login_required
@admin_required
def admin_user_detail(user_id):
    settings = SiteSettings.get_settings()
    user = db.session.get(User, user_id)
    domains = Domain.query.filter_by(user_id=user_id).all()
    
    return render_template('admin/user_detail.html', user=user, domains=domains, settings=settings)

# Kullanıcı banlama/banı kaldırma
@app.route('/admin/users/<int:user_id>/toggle-ban', methods=['POST'])
@login_required
@admin_required
def admin_toggle_user_ban(user_id):
    user = db.session.get(User, user_id)
    
    # Kendisini banlamamalı
    if user.id == current_user.id:
        flash('Kendinizi banlayamazsınız!', 'danger')
        return redirect(url_for('admin_user_detail', user_id=user_id))
    
    if user.is_banned:
        user.is_banned = False
        user.ban_reason = None
        flash(f'{user.username} kullanıcısının banı kaldırıldı.', 'success')
    else:
        user.is_banned = True
        user.ban_reason = request.form.get('ban_reason', 'Sebep belirtilmedi')
        flash(f'{user.username} kullanıcısı banlandı.', 'warning')
    
    db.session.commit()
    return redirect(url_for('admin_user_detail', user_id=user_id))

# Kullanıcı silme
@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    user = db.session.get(User, user_id)
    
    # Kendini silmeye çalışıyor mu?
    if user.id == current_user.id:
        flash('Kendinizi silemezsiniz!', 'danger')
        return redirect(url_for('admin_user_detail', user_id=user_id))
    
    # Kullanıcının tüm domainlerini sil
    Domain.query.filter_by(user_id=user.id).delete()
    
    # Kullanıcıyı sil
    username = user.username
    db.session.delete(user)
    db.session.commit()
    
    flash(f'{username} kullanıcısı ve tüm alan adları başarıyla silindi.', 'success')
    return redirect(url_for('admin_users'))

# Kullanıcıya admin yetkisi verme/alma
@app.route('/admin/users/<int:user_id>/toggle-admin', methods=['POST'])
@login_required
@admin_required
def admin_toggle_user_admin(user_id):
    user = db.session.get(User, user_id)
    
    # Kendisinin admin durumunu değiştirmemeli
    if user.id == current_user.id:
        flash('Kendi admin yetkinizi değiştiremezsiniz!', 'danger')
        return redirect(url_for('admin_user_detail', user_id=user_id))
    
    # Admin yetkisini değiştir
    user.is_admin = not user.is_admin
    db.session.commit()
    
    if user.is_admin:
        flash(f'{user.username} kullanıcısına admin yetkisi verildi.', 'success')
    else:
        flash(f'{user.username} kullanıcısının admin yetkisi kaldırıldı.', 'warning')
    
    return redirect(url_for('admin_user_detail', user_id=user_id))

# Admin - Tüm alan adları
@app.route('/admin/domains')
@login_required
@admin_required
def admin_domains():
    settings = SiteSettings.get_settings()
    
    # Filtreler ve sayfalama için parametreleri al
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search', '')
    registrar_filter = request.args.get('registrar', '')
    registrar_search = request.args.get('registrar_search', '')
    
    # Ana domain sorgusunu oluştur
    query = Domain.query
    
    # Alan adı araması
    if search_query:
        query = query.filter(Domain.domain_name.ilike(f'%{search_query}%'))
    
    # Kayıt firması filtresi
    if registrar_filter:
        if registrar_filter == 'empty':
            # Boş veya null kayıt firmaları için özel filtre
            query = query.filter(or_(Domain.registrar == None, Domain.registrar == ''))
        else:
            query = query.filter(Domain.registrar == registrar_filter)
    
    # Sıralama
    query = query.order_by(Domain.created_at.desc())
    
    # Sayfalama
    domains = query.paginate(page=page, per_page=settings.items_per_page, error_out=False)
    
    # TÜM registrar değerlerini al (boş olanları hariç)
    registrars = []
    
    # Filtreleme için registrar listesini oluştur
    # Registrar arama filtresi varsa, ona göre sınırla
    registrar_query = db.session.query(Domain.registrar.distinct())
    
    if registrar_search:
        registrar_query = registrar_query.filter(Domain.registrar.ilike(f'%{registrar_search}%'))
    
    # Filtrelenmiş sonuçları al
    for reg in registrar_query.all():
        # None veya boş string değilse listeye ekle
        if reg[0] and reg[0].strip():
            registrars.append(reg[0])
    
    # Alfabetik sırala
    registrars.sort()
    
    # Debug için konsola yazdır
    print(f"Bulunan kayıt firmaları ({len(registrars)}): {registrars}")
    
    # Boş veya Null registrar kayıtları var mı kontrol et
    empty_registrars_exist = db.session.query(Domain).filter(
        or_(Domain.registrar == None, Domain.registrar == '')
    ).first() is not None
    
    return render_template(
        'admin/domains.html', 
        domains=domains, 
        settings=settings, 
        search_query=search_query,
        registrar_filter=registrar_filter,
        registrar_search=registrar_search,
        registrars=registrars,
        empty_registrars_exist=empty_registrars_exist
    )

# Admin - Alan adı detayları
@app.route('/admin/domains/<int:domain_id>')
@login_required
@admin_required
def admin_domain_detail(domain_id):
    settings = SiteSettings.get_settings()
    domain = db.session.get(Domain, domain_id)
    if not domain:
        flash('Alan adı bulunamadı.', 'danger')
        return redirect(url_for('admin_domains'))
    
    # Domain sahibi
    owner = db.session.get(User, domain.user_id)
    
    # WHOIS bilgisi çıkarma
    whois_info = {}
    if domain.whois_data:
        for line in domain.whois_data.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                whois_info[key.strip()] = value.strip()
    
    # DNS kayıtları parse etme
    dns_records = {
        'A': domain.dns_a.split(',') if domain.dns_a else [],
        'NS': domain.nameservers.split(',') if domain.nameservers else [],
        'MX': domain.dns_mx.split(',') if domain.dns_mx else [],
        'TXT': domain.dns_txt.split(',') if domain.dns_txt else [],
        'CNAME': domain.cname_records.split(',') if domain.cname_records else []
    }
    
    return render_template(
        'admin/domain_detail.html', 
        domain=domain,
        owner=owner,
        whois_info=whois_info,
        dns_records=dns_records,
        settings=settings
    )

# Admin - Alan adı bilgilerini güncelleme
@app.route('/admin/domains/<int:domain_id>/refresh')
@login_required
@admin_required
def admin_domain_refresh(domain_id):
    domain = db.session.get(Domain, domain_id)
    if not domain:
        flash('Alan adı bulunamadı.', 'danger')
        return redirect(url_for('admin_domains'))
    
    try:
        # Alan adı bilgilerini güncelle
        domain_info = get_domain_info(domain.domain_name)
        
        # Güncellenen bilgileri kaydet
        domain.registrar = domain_info['registrar']
        domain.registration_date = domain_info['registration_date']
        domain.expiry_date = domain_info['expiry_date']
        domain.status = domain_info['status']
        domain.nameservers = ','.join(domain_info['nameservers']) if domain_info['nameservers'] else None
        domain.registrant_name = domain_info['registrant_name']
        domain.registrant_organization = domain_info['registrant_organization']
        domain.registrant_email = domain_info['registrant_email']
        domain.tech_name = domain_info['tech_name']
        domain.tech_organization = domain_info['tech_organization']
        domain.tech_email = domain_info['tech_email']
        domain.dns_a = ','.join(domain_info['dns_records']['A']) if domain_info['dns_records']['A'] else None
        domain.dns_mx = ','.join(domain_info['dns_records']['MX']) if domain_info['dns_records']['MX'] else None
        domain.dns_txt = ','.join(domain_info['dns_records']['TXT']) if domain_info['dns_records']['TXT'] else None
        domain.cname_records = ','.join(domain_info['dns_records'].get('CNAME', [])) if domain_info['dns_records'].get('CNAME') else None
        domain.updated_at = datetime.now()
        
        db.session.commit()
        
        flash('Alan adı bilgileri başarıyla güncellendi!', 'success')
    except Exception as e:
        flash(f'Alan adı bilgileri güncellenirken hata oluştu: {str(e)}', 'danger')
    
    return redirect(url_for('admin_domain_detail', domain_id=domain_id))

# Admin - Alan adı silme
@app.route('/admin/domains/<int:domain_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_domain(domain_id):
    domain = db.session.get(Domain, domain_id)
    if not domain:
        flash('Alan adı bulunamadı.', 'danger')
        return redirect(url_for('admin_domains'))
    
    db.session.delete(domain)
    db.session.commit()
    
    flash('Alan adı başarıyla silindi.', 'success')
    return redirect(url_for('admin_domains'))

# Admin - Site ayarları
@app.route('/admin/settings')
@login_required
@admin_required
def admin_settings():
    settings = SiteSettings.get_settings()
    
    # Sistem bilgilerini getir
    system_info = {
        'flask_version': flask.__version__,
        'python_version': platform.python_version(),
        'os': f"{platform.system()} {platform.version()}",
        'db_uri': app.config.get('SQLALCHEMY_DATABASE_URI', 'sqlite:///domains.db'),
        'app_last_modified': datetime.fromtimestamp(os.path.getmtime(__file__)).strftime('%Y-%m-%d %H:%M:%S')
    }
    
    return render_template('admin/settings.html', settings=settings, system_info=system_info)

# Admin - Site ayarlarını güncelleme
@app.route('/admin/settings/update', methods=['POST'])
@login_required
@admin_required
def admin_settings_update():
    settings = SiteSettings.get_settings()
    
    # Form verilerini al
    settings.site_name = request.form.get('site_name')
    settings.contact_email = request.form.get('contact_email')
    settings.footer_text = request.form.get('footer_text')
    settings.maintenance_mode = 'maintenance_mode' in request.form
    settings.maintenance_message = request.form.get('maintenance_message')
    settings.items_per_page = int(request.form.get('items_per_page', 10))
    settings.max_whois_cache_days = int(request.form.get('max_whois_cache_days', 7))
    settings.allow_registration = 'allow_registration' in request.form
    settings.email_confirmation_required = 'email_confirmation_required' in request.form
    settings.last_updated = datetime.now()
    
    db.session.commit()
    
    flash('Site ayarları başarıyla güncellendi!', 'success')
    return redirect(url_for('admin_settings'))

# Create database tables
def create_tables():
    with app.app_context():
        # Tabloları oluştur
        db.create_all()
        
        # Admin kullanıcısı var mı kontrol et
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            # Varsayılan admin kullanıcısı oluştur
            admin_password = generate_password_hash('admin')
            admin = User(
                username='admin',
                email='admin@example.com',
                password=admin_password,
                is_admin=True
            )
            db.session.add(admin)
            
            # Varsayılan site ayarlarını oluştur
            settings = SiteSettings()
            db.session.add(settings)
            
            db.session.commit()
            print("Admin kullanıcısı ve varsayılan ayarlar oluşturuldu.")
        
        print("Database tabloları hazır.")

if __name__ == '__main__':
    with app.app_context():
        create_tables()
    app.run(debug=True)
