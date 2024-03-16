
from flask import Flask
from flask_cors import CORS
from flask_restful import Api
from certificate import CrearCertificados
import certificate

def create_flask_app():
    app = Flask(__name__)
    app.config["JWT_SECRET_KEY"] = "frase-secreta"
    app.config["PROPAGATE_EXCEPTIONS"] = True

    app_context = app.app_context()
    app_context.push()
    add_urls(app)
    CORS(app)
    certificate.initialize_certificates()

    return app


def add_urls(app):
    api = Api(app)
    api.add_resource(CrearCertificados, '/crearcertificado')

app = create_flask_app()

if __name__ == "__main__":
    app.run()
