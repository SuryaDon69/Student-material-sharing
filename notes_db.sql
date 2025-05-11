CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) UNIQUE,
    password VARCHAR(100),
    role ENUM('user', 'admin')
);
ALTER TABLE users ADD COLUMN first_name VARCHAR(100);
ALTER TABLE users ADD COLUMN last_name VARCHAR(100);
ALTER TABLE users ADD COLUMN email VARCHAR(100);
ALTER TABLE users ADD COLUMN phone VARCHAR(20);


CREATE TABLE notes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    title VARCHAR(200),
    subject VARCHAR(100),
    stream VARCHAR(100),
    filename VARCHAR(200),
    status ENUM('pending', 'acceptsed', 'rejected'),
    FOREIGN KEY (user_id) REFERENCES users(id)
);
INSERT INTO users(username, password, role) VALUES ('admin', 'admin123', 'admin');

CREATE TABLE chat_messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sender_id INT,
    receiver_id INT,
    message TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users(id),
    FOREIGN KEY (receiver_id) REFERENCES users(id)
);
ALTER TABLE chat_messages ADD COLUMN is_read BOOLEAN DEFAULT FALSE;

ALTER TABLE notes 
MODIFY status ENUM('pending', 'approved', 'rejected');

CREATE TABLE admin (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
);
INSERT INTO admin (username, password)
VALUES ('admin', 'admin123');
