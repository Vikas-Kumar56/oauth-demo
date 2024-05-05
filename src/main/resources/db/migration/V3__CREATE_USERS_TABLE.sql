create table users(
   username varchar(200) not null primary key,
   password varchar(500) not null,
   enabled boolean not null
);

create table authorities (
  username varchar(200) not null,
  authority varchar(200) not null,
  constraint fk_authorities_users foreign key(username) references users(username)
);