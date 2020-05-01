--------------------------------------------------------------------------------
-- Membership Database Schema
-- https://github.com/membership/membership.db
--
-- Copyright © 2016 Membership Database contributors.
--
-- This source code is licensed under the MIT license found in the
-- LICENSE.txt file in the root directory of this source tree.
--------------------------------------------------------------------------------

CREATE TABLE Users
(
  id                    INTEGER PRIMARY KEY,
  userName              TEXT,
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
  CONSTRAINT Users_ck_emailConfirmed CHECK (emailConfirmed IN (0, 1)),
  CONSTRAINT Users_ck_phoneNumberConfirmed CHECK (phoneNumberConfirmed IN (0, 1)),
  CONSTRAINT Users_ck_twoFactorEnabled CHECK (twoFactorEnabled IN (0, 1)),
  CONSTRAINT Users_ck_lockoutEnabled CHECK (lockoutEnabled IN (0, 1)),
  CONSTRAINT Users_ck_passwordResetRequired CHECK (passwordResetRequired IN (0, 1)),
  CONSTRAINT Users_ck_enabled CHECK (enabled IN (0, 1))
);

CREATE TABLE UserClaims
(
  id     INTEGER PRIMARY KEY,
  userId INTEGER NOT NULL,
  claimType   TEXT,
  claimValue  TEXT,
  -- Keys
  CONSTRAINT UserClaims_fk_userId FOREIGN KEY (userId)
    REFERENCES Users (id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX Users_ix_email ON Users (email);
CREATE INDEX UserClaims_ix_userId ON UserClaims (userId);
