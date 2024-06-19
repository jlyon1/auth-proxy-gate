CREATE TABLE accounts
(
    id       string,
    username string,
    email    string
);

CREATE TABLE providers
(
    id   string,
    name string
);

INSERT INTO providers (id, name) VALUES ("google", "google"), ("unsafe", "unsafe");

CREATE TABLE accounts_providers
(
    provider_id         string,
    account_id          string,
    provider_account_id string,
    FOREIGN KEY (provider_id) REFERENCES providers(id),
    FOREIGN KEY (account_id) REFERENCES accounts(id)
);