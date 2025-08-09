import os
import random
import string
import io
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
import qrcode
from PIL import Image, ImageDraw, ImageFont

app = Flask(__name__)
app.secret_key = 'clave_super_secreta'

DB = 'mascotas.db'
UPLOAD_FOLDER = 'static/uploads'
QR_FOLDER = 'static/qr_codes'  # Carpeta para QR con texto
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
if not os.path.exists(QR_FOLDER):
    os.makedirs(QR_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def crear_tablas():
    conn = get_db()
    conn.executescript('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL,
        apellido TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        telefono TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS qr_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        codigo TEXT UNIQUE NOT NULL,
        asignado INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS mascotas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        qr_code_id INTEGER NOT NULL,
        nombre TEXT NOT NULL,
        raza TEXT,
        descripcion TEXT,
        foto TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(qr_code_id) REFERENCES qr_codes(id)
    );
    ''')
    conn.commit()
    conn.close()

crear_tablas()

def generar_codigo_qr_unico():
    conn = get_db()
    while True:
        codigo = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        existe = conn.execute('SELECT 1 FROM qr_codes WHERE codigo=?', (codigo,)).fetchone()
        if not existe:
            conn.close()
            return codigo

def generar_qr_con_codigo_texto(codigo):
    url = url_for('pagina_mascota', codigo=codigo, _external=True)
    qr = qrcode.QRCode(box_size=10, border=4)
    qr.add_data(url)
    qr.make(fit=True)
    img_qr = qr.make_image(fill_color="black", back_color="white").convert('RGB')

    ancho, alto = img_qr.size
    alto_texto = 30
    nueva_img = Image.new('RGB', (ancho, alto + alto_texto), 'white')
    nueva_img.paste(img_qr, (0, 0))

    draw = ImageDraw.Draw(nueva_img)
    try:
        font = ImageFont.truetype("arial.ttf", 20)
    except:
        font = ImageFont.load_default()

    bbox = draw.textbbox((0, 0), codigo, font=font)  # método correcto para PIL >=8.0
    w = bbox[2] - bbox[0]
    h = bbox[3] - bbox[1]

    x = (ancho - w) // 2
    y = alto + (alto_texto - h) // 2
    draw.text((x, y), codigo, fill="black", font=font)

    return nueva_img


@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('panel_usuario'))
    return redirect(url_for('login'))

@app.route('/registro', methods=['GET','POST'])
def registro():
    if request.method == 'POST':
        nombre = request.form['nombre']
        apellido = request.form['apellido']
        email = request.form['email'].lower()
        telefono = request.form['telefono'].replace(' ', '').replace('-', '')
        if not telefono.startswith('+549'):
            telefono = '+549' + telefono.lstrip('0').lstrip('+')
        password = request.form['password']
        password_hash = generate_password_hash(password)

        conn = get_db()
        try:
            conn.execute('INSERT INTO users (nombre, apellido, email, telefono, password_hash) VALUES (?, ?, ?, ?, ?)',
                         (nombre, apellido, email, telefono, password_hash))
            conn.commit()
            flash('Registro exitoso, ya puede ingresar.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email o teléfono ya registrado.', 'danger')
        finally:
            conn.close()
    return render_template('registro.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].lower()
        password = request.form['password']
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['user_nombre'] = user['nombre']
            flash(f'Bienvenido {user["nombre"]}', 'success')
            return redirect(url_for('panel_usuario'))
        else:
            flash('Credenciales inválidas.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Sesión cerrada.', 'info')
    return redirect(url_for('login'))

@app.route('/panel_usuario', methods=['GET','POST'])
def panel_usuario():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()

    if request.method == 'POST':
        nombre_mascota = request.form['nombre_mascota']
        raza = request.form.get('raza')
        descripcion = request.form.get('descripcion')
        qr_code = request.form['qr_code'].strip().upper()

        qr = conn.execute('SELECT * FROM qr_codes WHERE codigo=?', (qr_code,)).fetchone()
        if not qr:
            flash('Código QR no válido.', 'danger')
            conn.close()
            return redirect(url_for('panel_usuario'))
        if qr['asignado']:
            flash('Código QR ya asignado a otra mascota.', 'danger')
            conn.close()
            return redirect(url_for('panel_usuario'))

        file = request.files.get('foto')
        nombre_archivo = None
        if file and allowed_file(file.filename):
            ext = file.filename.rsplit('.',1)[1].lower()
            nombre_archivo = f"{qr_code}.{ext}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], nombre_archivo)
            file.save(filepath)

        conn.execute('''
            INSERT INTO mascotas (user_id, qr_code_id, nombre, raza, descripcion, foto)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (session['user_id'], qr['id'], nombre_mascota, raza, descripcion, nombre_archivo))

        conn.execute('UPDATE qr_codes SET asignado=1 WHERE id=?', (qr['id'],))
        conn.commit()

        flash('Mascota registrada con éxito.', 'success')

    mascotas = conn.execute('''
        SELECT m.*, q.codigo FROM mascotas m
        JOIN qr_codes q ON m.qr_code_id = q.id
        WHERE m.user_id=?
    ''', (session['user_id'],)).fetchall()

    conn.close()

    return render_template('panel_usuario.html', mascotas=mascotas)

@app.route('/mascota/<codigo>')
def pagina_mascota(codigo):
    conn = get_db()
    qr = conn.execute('SELECT * FROM qr_codes WHERE codigo=?', (codigo,)).fetchone()
    if not qr:
        conn.close()
        return 'Código QR inválido.', 404
    if qr['asignado'] != 1:
        conn.close()
        return 'Código QR no asignado.', 404

    mascota = conn.execute('''
        SELECT m.*, u.nombre AS nombre_dueño, u.telefono 
        FROM mascotas m
        JOIN users u ON m.user_id = u.id
        WHERE m.qr_code_id=?
    ''', (qr['id'],)).fetchone()
    conn.close()
    if not mascota:
        return 'Mascota no encontrada.', 404

    # URL para enviar ubicación vía WhatsApp, se puede armar con JS en la plantilla
    return render_template('pagina_mascota.html', mascota=mascota)

@app.route('/descargar_qr/<codigo>')
def descargar_qr(codigo):
    img_qr = generar_qr_con_codigo_texto(codigo)
    buf = io.BytesIO()
    img_qr.save(buf, format='PNG')
    buf.seek(0)
    return send_file(buf, mimetype='image/png', download_name=f'QR_{codigo}.png')


@app.route('/admin', methods=['GET','POST'])
def admin():
    if request.method == 'POST':
        cantidad = request.form.get('cantidad')
        if not cantidad or not cantidad.isdigit() or int(cantidad) < 1:
            flash('Cantidad inválida.', 'danger')
            return redirect(url_for('admin'))
        cantidad = int(cantidad)
        conn = get_db()
        nuevos_codigos = []
        for _ in range(cantidad):
            codigo = generar_codigo_qr_unico()
            conn.execute('INSERT INTO qr_codes (codigo) VALUES (?)', (codigo,))

            # Generar QR con código impreso y guardarlo
            img_qr = generar_qr_con_codigo_texto(codigo)
            img_qr.save(os.path.join(QR_FOLDER, f'qr_{codigo}.png'))

            nuevos_codigos.append(codigo)
        conn.commit()
        conn.close()
        flash(f'Se generaron {cantidad} códigos QR.', 'success')
        return render_template('admin.html', nuevos_codigos=nuevos_codigos)
    return render_template('admin.html')

if __name__ == '__main__':
    app.run(debug=True)
