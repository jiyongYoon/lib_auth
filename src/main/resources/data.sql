INSERT INTO tb_user(user_id, user_email, user_password, user_role) VALUES
                 (1, 'test1', 'test', 'ROLE_ADMIN'),
                 (2, 'test2', '$2a$10$.6MNoZ2JNZIrOf0XKOVrReoQA8Tg6kY9nymRmIodXERrBIEfNdM3.', 'ROLE_USER'),
                 (3, 'test3', '{noop}test', 'ROLE_ADMIN'),
                 (4, 'test4', '{bcrypt}test', 'ROLE_ADMIN')
;