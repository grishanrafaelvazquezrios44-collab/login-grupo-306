from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "clave-secreta-login")

def conectar():
    return sqlite3.connect("usuarios.db")

def crear_tabla():
    with conectar() as db:
        db.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT,
            usuario TEXT UNIQUE,
            correo TEXT,
            password TEXT
        )
        """)

crear_tabla()

@app.route("/")
def login():
    return render_template("login.html")

@app.route("/registrar", methods=["GET", "POST"])
def registrar():
    if request.method == "POST":
        nombre = request.form["nombre"]
        usuario = request.form["usuario"]
        correo = request.form["correo"]
        password = generate_password_hash(request.form["password"])

        try:
            with conectar() as db:
                db.execute(
                    "INSERT INTO usuarios (nombre, usuario, correo, password) VALUES (?, ?, ?, ?)",
                    (nombre, usuario, correo, password)
                )
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            return "Ese usuario ya existe"

    return render_template("registro.html")

@app.route("/acceder", methods=["POST"])
def acceder():
    identificador = request.form["identificador"]
    password = request.form["password"]

    with conectar() as db:
        usuario = db.execute(
            "SELECT * FROM usuarios WHERE usuario=? OR correo=?",
            (identificador, identificador)
        ).fetchone()

    if usuario and check_password_hash(usuario[4], password):
        session["usuario"] = usuario[2]
        session["nombre"] = usuario[1]
        return redirect(url_for("inicio"))

    return redirect(url_for("login"))

@app.route("/inicio")
def inicio():
    if "usuario" not in session:
        return redirect(url_for("login"))
    return render_template("inicio.html")

@app.route("/salir")
def salir():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run()
