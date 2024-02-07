from flask import Flask, jsonify, request
import sqlite3

app = Flask(__name__)


@app.route('/activate', methods=['POST'])
def register_activate_request():
    conn = sqlite3.connect('my_database.db')
    data = request.get_json()
    conn.close
    return 'This is a test'




if __name__ == '__main__':
    app.run(debug=True)
