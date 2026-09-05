from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/")
def home():
    return jsonify({
        "service": "Test Backend API",
        "status": "running"
    })


@app.route("/api/hello")
def hello():
    return jsonify({
        "message": "Hello from the backend API",
        "gateway_test": True
    })


@app.route("/api/data", methods=["GET", "POST"])
def data():

    if request.method == "POST":
        body = request.get_json(silent=True)

        return jsonify({
            "message": "Data received by backend",
            "data": body
        })

    return jsonify({
        "message": "Backend data endpoint",
        "method": "GET"
    })


@app.route("/health")
def health():
    return jsonify({
        "backend": "healthy"
    })


if __name__ == "__main__":
    print("=====================================")
    print(" Test Backend API")
    print("=====================================")
    print(" Listening on http://127.0.0.1:5000")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
