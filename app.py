from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Configuración de la base de datos y la sesión
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///joyeria.db'
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SESSION_TYPE'] = 'filesystem'
db = SQLAlchemy(app)

# Modelo de Usuario
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

# Crear la base de datos si no existe
with app.app_context():
    db.create_all()

# Ruta para la página principal
@app.route('/')
def index():
    return render_template('index.html')

# Ruta de Registro
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Verificar si el usuario ya existe
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('El nombre de usuario ya está en uso. Elige otro.', 'danger')
            return redirect(url_for('register'))

        # Guardar el usuario con contraseña encriptada
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Usuario registrado exitosamente. Ahora puedes iniciar sesión.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# Ruta de Inicio de Sesión
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Verificar usuario y contraseña
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id  # Almacena el ID del usuario en la sesión
            flash('Inicio de sesión exitoso.', 'success')
            return redirect(url_for('productos'))
        else:
            flash('Credenciales incorrectas.', 'danger')

    return render_template('login.html')

# Ruta para Cerrar Sesión
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Has cerrado sesión.', 'success')
    return redirect(url_for('index'))

# Ruta para mostrar productos
@app.route('/productos')
def productos():
    # Aquí puedes consultar la base de datos para mostrar productos
    # Asegúrate de que hay algo que mostrar
    return render_template('productos.html')

# Inicializar el carrito y agregar productos
@app.route('/add_to_cart/<int:product_id>')
def add_to_cart(product_id):
    if 'cart' not in session:
        session['cart'] = []

    session['cart'].append(product_id)
    session.modified = True  # Indica que la sesión se ha modificado
    flash('Producto agregado al carrito.', 'success')
    return redirect(url_for('productos'))

# Ver contenido del carrito
@app.route('/cart')
def cart():
    cart_items = session.get('cart', [])  # Recupera el carrito desde la sesión
    return render_template('cart.html', cart_items=cart_items)

# Eliminar productos del carrito
@app.route('/remove_from_cart/<int:product_id>')
def remove_from_cart(product_id):
    if 'cart' in session and product_id in session['cart']:
        session['cart'].remove(product_id)
        session.modified = True
        flash('Producto eliminado del carrito.', 'success')
    return redirect(url_for('cart'))
@app.route('/')
def home():
    return '¡Hola, mundo desde Flask en Render!'
# Iniciar la aplicación
if __name__ == '__main__':
    app.run(debug=True)
