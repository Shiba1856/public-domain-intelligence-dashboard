"""Entry point: start the dashboard on this computer only."""
from app import create_app

app = create_app()

if __name__ == "__main__":
    # 127.0.0.1 means only THIS computer can open the app (other devices on the
    # network cannot use it to send requests). debug=False so error pages never
    # reveal stack traces or configuration.
    app.run(host="127.0.0.1", port=5000, debug=False)