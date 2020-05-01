--------------------------------------------------------------------------------
-- Membership Database Schema
-- https://github.com/membership/membership.db
--
-- Copyright © 2016 Membership Database contributors.
--
-- This source code is licensed under the MIT license found in the
-- LICENSE.txt file in the root directory of this source tree.
--------------------------------------------------------------------------------

CREATE TABLE User
(
  id                    INTEGER PRIMARY KEY,
  firstName             TEXT,
  lastName              TEXT,
  caption               TEXT,
  email                 TEXT,
  emailConfirmed        NUMERIC NOT NULL DEFAULT 0,
  passwordHash          TEXT,
  securityStamp         TEXT,
  concurrencyStamp      TEXT    NOT NULL DEFAULT (lower(hex(randomblob(16)))),
  phoneNumber           TEXT,
  phoneNumberConfirmed  NUMERIC NOT NULL DEFAULT 0,
  twoFactorEnabled      NUMERIC NOT NULL DEFAULT 0,
  lockoutEnd            TEXT,
  lockoutEnabled        NUMERIC NOT NULL DEFAULT 0,
  accessFailedCount     INTEGER NOT NULL DEFAULT 0,
  passwordResetRequired NUMERIC NOT NULL DEFAULT 0,
  enabled               NUMERIC NOT NULL DEFAULT 0,
  -- Constraints
  CONSTRAINT User_ck_emailConfirmed CHECK (emailConfirmed IN (0, 1)),
  CONSTRAINT User_ck_phoneNumberConfirmed CHECK (phoneNumberConfirmed IN (0, 1)),
  CONSTRAINT User_ck_twoFactorEnabled CHECK (twoFactorEnabled IN (0, 1)),
  CONSTRAINT User_ck_lockoutEnabled CHECK (lockoutEnabled IN (0, 1)),
  CONSTRAINT User_ck_passwordResetRequired CHECK (passwordResetRequired IN (0, 1)),
  CONSTRAINT User_ck_enabled CHECK (enabled IN (0, 1))
);

CREATE TABLE UserClaim
(
  id     INTEGER PRIMARY KEY,
  userId INTEGER NOT NULL,
  type   TEXT,
  value  TEXT,
  -- Keys
  CONSTRAINT UserClaim_fk_userId FOREIGN KEY (userId)
    REFERENCES User (id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE UserRole
(
  id   INTEGER PRIMARY KEY,
  name TEXT    NOT NULL,
  -- Keys
  CONSTRAINT UserRole_uk_name UNIQUE (name)
);

CREATE TABLE UserLogin (
  name   TEXT    NOT NULL,
  key    TEXT    NOT NULL,
  userId INTEGER NOT NULL,
  -- Keys
  CONSTRAINT UserLogin_pk_name_key PRIMARY KEY (name, key),
  CONSTRAINT UserLogin_fk_userId FOREIGN KEY (userId)
    REFERENCES User (id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE UserUserRole
(
  userId INTEGER NOT NULL,
  roleId INTEGER NOT NULL,
  -- Keys
  CONSTRAINT UserUserRole_pk_userId_roleId PRIMARY KEY (userId, roleId),
  CONSTRAINT UserUserRole_fk_userId FOREIGN KEY (userId)
    REFERENCES User (id) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT UserUserRole_fk_roleId FOREIGN KEY (roleId)
    REFERENCES UserRole (id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX User_ix_email ON User (email);
CREATE INDEX UserClaim_ix_userId ON UserClaim (userId);
CREATE INDEX UserLogin_ix_userId ON UserLogin (userId);
CREATE INDEX UserUserRole_ix_userId ON UserUserRole (userId);
CREATE INDEX UserUserRole_ix_roleId ON UserUserRole (roleId);
