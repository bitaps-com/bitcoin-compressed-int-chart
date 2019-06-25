CREATE TABLE IF NOT EXISTS blocks (height BIGINT NOT NULL,
                                   timestamp INT4,
                                   size_c_int INT4,
                                   size_v_int INT4,
                                   PRIMARY KEY(height));

CREATE TABLE IF NOT EXISTS blocks_daily (day BIGINT NOT NULL,
                                         size_c_int INT4,
                                         size_v_int INT4,
                                         PRIMARY KEY(day));

CREATE TABLE IF NOT EXISTS blocks_daily (month VARCHAR NOT NULL,
                                         size_c_int INT4,
                                         size_v_int INT4,
                                         PRIMARY KEY(month));