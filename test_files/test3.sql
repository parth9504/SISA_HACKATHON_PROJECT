-- PostgreSQL database dump
-- Dumped from database version 14.2
-- Date: 2026-03-24

CREATE TABLE public.users (
    id integer NOT NULL,
    username character varying(50),
    email character varying(255),
    pwd_hash character varying(255)
);

INSERT INTO public.users (id, username, email, pwd_hash) VALUES (1, 'sysadmin', 'admin@finmate.local', 'password=admin1234');
INSERT INTO public.users (id, username, email, pwd_hash) VALUES (2, 'testuser', 'test@example.com', 'password=qwerty');
INSERT INTO public.users (id, username, email, pwd_hash) VALUES (3, 'p.hemdan', 'parth.demo@company.com', 'password=Pa$$w0rd!');

ALTER TABLE ONLY public.users ADD CONSTRAINT users_pkey PRIMARY KEY (id);