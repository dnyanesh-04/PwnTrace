from flask import Flask

from app.routes.main_routes import main


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object("config.Config")

    app.register_blueprint(main)

    # Ensure output directories exist at startup.
    app.config["REPORT_DIR"].mkdir(parents=True, exist_ok=True)
    app.config["EXPORT_DIR"].mkdir(parents=True, exist_ok=True)

    return app
