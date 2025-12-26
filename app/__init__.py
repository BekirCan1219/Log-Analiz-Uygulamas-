from flask import Flask
from .config import Config
from .extensions import db
from .services.scheduler import start_scheduler

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # ✅ SESSION için zorunlu
    app.config["SECRET_KEY"] = app.config.get("SECRET_KEY") or "dev-secret-key"

    start_scheduler(app)
    db.init_app(app)

    # Blueprints
    from .controllers.ingest_controller import ingest_bp
    from .controllers.metrics_controller import metrics_bp
    from .controllers.alerts_controller import alerts_bp
    from .controllers.dashboard_controller import dashboard_bp
    from .controllers.discover_controller import discover_bp
    from .controllers.search_controller import search_bp
    from .controllers.pages_controller import pages_bp
    from .controllers.auth_controller import auth_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(pages_bp)
    app.register_blueprint(alerts_bp, name="alerts_api")
    app.register_blueprint(search_bp)
    app.register_blueprint(discover_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(ingest_bp)
    app.register_blueprint(metrics_bp)

    with app.app_context():
        db.create_all()

    return app
