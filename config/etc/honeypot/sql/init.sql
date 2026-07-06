CREATE DATABASE IF NOT EXISTS honeypot;
USE honeypot;

-- Users ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(50)  NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    email         VARCHAR(100) NOT NULL UNIQUE,
    avatar        VARCHAR(255) DEFAULT NULL,
    is_admin      TINYINT(1)   DEFAULT 0,
    is_enabled    TINYINT(1)   DEFAULT 1,
    created_at    TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
);

-- Todos ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS todos (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    user_id    INT          NOT NULL,
    title      VARCHAR(255) NOT NULL,
    is_done    TINYINT(1)   DEFAULT 0,
    created_at TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Activity / Security log ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS activity_log (
    id                 INT AUTO_INCREMENT PRIMARY KEY,
    event_type         VARCHAR(50)  NOT NULL,
    user_id            INT          DEFAULT NULL,
    username_attempted VARCHAR(100) DEFAULT NULL,
    ip_address         VARCHAR(45)  NOT NULL,
    user_agent         TEXT         DEFAULT NULL,
    details            TEXT         DEFAULT NULL,
    created_at         TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_event   (event_type),
    INDEX idx_ip      (ip_address),
    INDEX idx_created (created_at)
);

-- Honeypot trap log ─────────────────────────────────────────────────────────
-- full POST data, all headers, etc.
-- This feeds separate Kibana dashboards.
CREATE TABLE IF NOT EXISTS honeypot_log (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    trap_name    VARCHAR(100) NOT NULL,    -- 'fakeAdmin_login', 'honeyPotAdmin_dashboard', 'env_file', etc.
    layer        VARCHAR(30)  NOT NULL,    -- 'fakeAdmin', 'honeyPotAdmin', 'trap'
    source_ip    VARCHAR(45)  NOT NULL,
    method       VARCHAR(10)  NOT NULL,
    request_uri  TEXT         NOT NULL,
    user_agent   TEXT         DEFAULT NULL,
    referer      TEXT         DEFAULT NULL,
    details      JSON         DEFAULT NULL, -- full POST data, headers, cookies, detected tool
    created_at   TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_hp_trap    (trap_name),
    INDEX idx_hp_layer   (layer),
    INDEX idx_hp_ip      (source_ip),
    INDEX idx_hp_created (created_at)
);

-- Seed users ────────────────────────────────────────────────────────────────
-- All the passwords: Admin@Honey1234!

INSERT INTO users (username, password_hash, email, is_admin, is_enabled) VALUES
('admin',
 '$2y$12$LzNqbMXLUqHjUzxLNJ6MreuDH8Fzhu2oBhTq0PH5Dv3vKrA1Lm9.e',
 'admin@honeypot.local', 1, 1),
('pooh',
 '$2y$12$LzNqbMXLUqHjUzxLNJ6MreuDH8Fzhu2oBhTq0PH5Dv3vKrA1Lm9.e',
 'pooh@hundredacre.local', 0, 1),
('piglet',
 '$2y$12$LzNqbMXLUqHjUzxLNJ6MreuDH8Fzhu2oBhTq0PH5Dv3vKrA1Lm9.e',
 'piglet@hundredacre.local', 0, 0),
('tigger',
 '$2y$12$LzNqbMXLUqHjUzxLNJ6MreuDH8Fzhu2oBhTq0PH5Dv3vKrA1Lm9.e',
 'tigger@hundredacre.local', 0, 1),
('eeyore',
 '$2y$12$LzNqbMXLUqHjUzxLNJ6MreuDH8Fzhu2oBhTq0PH5Dv3vKrA1Lm9.e',
 'eeyore@hundredacre.local', 0, 1),
('rabbit',
 '$2y$12$LzNqbMXLUqHjUzxLNJ6MreuDH8Fzhu2oBhTq0PH5Dv3vKrA1Lm9.e',
 'rabbit@hundredacre.local', 0, 1),
('owl',
 '$2y$12$LzNqbMXLUqHjUzxLNJ6MreuDH8Fzhu2oBhTq0PH5Dv3vKrA1Lm9.e',
 'owl@hundredacre.local', 0, 1),
('kanga',
 '$2y$12$LzNqbMXLUqHjUzxLNJ6MreuDH8Fzhu2oBhTq0PH5Dv3vKrA1Lm9.e',
 'kanga@hundredacre.local', 0, 1);

-- Seed todos ────────────────────────────────────────────────────────────────
INSERT INTO todos (user_id, title, is_done, created_at) VALUES
(2, 'Find more hunny pots',              0, DATE_SUB(NOW(), INTERVAL 21 DAY)),
(2, 'Visit Rabbit for lunch',            1, DATE_SUB(NOW(), INTERVAL 18 DAY)),
(2, 'Count honey jars in the cupboard',  0, DATE_SUB(NOW(), INTERVAL 14 DAY)),
(2, 'Say good morning to Piglet',        1, DATE_SUB(NOW(), INTERVAL 10 DAY)),
(2, 'Fix the bell on the front door',    0, DATE_SUB(NOW(), INTERVAL 5 DAY)),
(4, 'Practice bouncing',                 1, DATE_SUB(NOW(), INTERVAL 12 DAY)),
(4, 'Find something to bounce on',       0, DATE_SUB(NOW(), INTERVAL 3 DAY)),
(5, 'Find my tail',                      0, DATE_SUB(NOW(), INTERVAL 25 DAY)),
(5, 'Try not to lose tail again',        0, DATE_SUB(NOW(), INTERVAL 2 DAY)),
(6, 'Organise the garden',               1, DATE_SUB(NOW(), INTERVAL 8 DAY)),
(7, 'Read encyclopaedia volume 7',       0, DATE_SUB(NOW(), INTERVAL 6 DAY));

-- Seed activity log ─────────────────────────────────────────────────────────
INSERT INTO activity_log (event_type, user_id, username_attempted, ip_address, user_agent, details, created_at) VALUES
('LOGIN_SUCCESS', 1, 'admin',  '127.0.0.1',     'Mozilla/5.0 (initial setup)',    '{}', DATE_SUB(NOW(), INTERVAL 14 DAY)),
('LOGIN_SUCCESS', 2, 'pooh',   '192.168.1.10',  'Mozilla/5.0',                    '{}', DATE_SUB(NOW(), INTERVAL 13 DAY)),
('LOGIN_FAIL',   NULL, 'admin','185.220.101.47', 'sqlmap/1.7',                     '{"reason":"bad password"}', DATE_SUB(NOW(), INTERVAL 10 DAY)),
('LOGIN_FAIL',   NULL, 'admin','185.220.101.47', 'sqlmap/1.7',                     '{"reason":"bad password"}', DATE_SUB(NOW(), INTERVAL 10 DAY)),
('LOGIN_FAIL',   NULL, 'root', '185.220.101.47', 'curl/7.88',                      '{"reason":"user not found"}', DATE_SUB(NOW(), INTERVAL 10 DAY)),
('REGISTER',      3, 'piglet', '192.168.1.11',  'Mozilla/5.0',                    '{"email":"piglet@hundredacre.local"}', DATE_SUB(NOW(), INTERVAL 12 DAY)),
('LOGIN_SUCCESS', 4, 'tigger', '192.168.1.12',  'Mozilla/5.0',                    '{}', DATE_SUB(NOW(), INTERVAL 7 DAY)),
('REGISTER',      6, 'rabbit', '192.168.1.15',  'Mozilla/5.0',                    '{"email":"rabbit@hundredacre.local"}', DATE_SUB(NOW(), INTERVAL 9 DAY)),
('LOGIN_FAIL',   NULL,'administrator','45.155.205.233','python-requests/2.31.0',   '{"reason":"user not found"}', DATE_SUB(NOW(), INTERVAL 5 DAY)),
('LOGIN_FAIL',   NULL,'sa',    '45.155.205.233', 'python-requests/2.31.0',         '{"reason":"user not found"}', DATE_SUB(NOW(), INTERVAL 5 DAY));

-- Chat messages ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS messages (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  content TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_user_created (user_id, created_at)
);

-- Seed chat messages ───────────────────────────────────────────────────────
INSERT INTO messages (user_id, content, created_at) VALUES
(2, 'Has anyone seen my honey pot? I left it near the oak tree.',  DATE_SUB(NOW(), INTERVAL 15 DAY)),
(4, 'The wonderful thing about tiggers is tiggers are wonderful things!', DATE_SUB(NOW(), INTERVAL 14 DAY)),
(5, 'Nobody ever notices me anyway.',                                DATE_SUB(NOW(), INTERVAL 13 DAY)),
(6, 'Please stay OUT of my garden. I mean it this time.',           DATE_SUB(NOW(), INTERVAL 11 DAY)),
(2, 'Think think think...',                                         DATE_SUB(NOW(), INTERVAL 10 DAY)),
(7, 'Did you know that the term "honeycomb" derives from the Old English word "hunigcamb"?', DATE_SUB(NOW(), INTERVAL 9 DAY)),
(4, 'Bounced right into Rabbit''s house again! Hoo hoo hoo!',      DATE_SUB(NOW(), INTERVAL 7 DAY)),
(8, 'Roo, please come home for lunch, dear.',                       DATE_SUB(NOW(), INTERVAL 5 DAY)),
(2, 'Oh bother. The maze is harder than I thought.',                DATE_SUB(NOW(), INTERVAL 3 DAY)),
(5, 'I got a score of 42 in the maze. Not that anyone cares.',     DATE_SUB(NOW(), INTERVAL 2 DAY)),
(6, 'I got 187! Organisation is the key.',                          DATE_SUB(NOW(), INTERVAL 1 DAY));

-- Game scores ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS game_scores (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  game VARCHAR(50) NOT NULL,
  score INT NOT NULL,
  time_sec DECIMAL(8,2) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_game_user (game, user_id),
  INDEX idx_game_score (game, score),
  INDEX idx_user_game (user_id, game)
);

-- Seed game scores ─────────────────────────────────────────────────────────
INSERT INTO game_scores (user_id, game, score, time_sec, created_at) VALUES
(2, 'maze', 85,  32.4, DATE_SUB(NOW(), INTERVAL 12 DAY)),
(2, 'maze', 112, 28.1, DATE_SUB(NOW(), INTERVAL 8 DAY)),
(4, 'maze', 156, 19.7, DATE_SUB(NOW(), INTERVAL 10 DAY)),
(4, 'maze', 203, 15.2, DATE_SUB(NOW(), INTERVAL 5 DAY)),
(5, 'maze', 42,  68.3, DATE_SUB(NOW(), INTERVAL 3 DAY)),
(6, 'maze', 187, 16.8, DATE_SUB(NOW(), INTERVAL 2 DAY)),
(7, 'maze', 95,  35.6, DATE_SUB(NOW(), INTERVAL 6 DAY)),
(1, 'maze', 220, 12.1, DATE_SUB(NOW(), INTERVAL 1 DAY));
