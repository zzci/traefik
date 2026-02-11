# traefik

```
git clone https://github.com/zzci/traefik.git

cd traefik

cp -a env.example .env

./aa run
```

## plugin

https://github.com/soulbalz/traefik-real-ip

```yml
http:
  middlewares:
    my-traefik-real-ip:
      plugin:
        traefik-real-ip:
          excludednets:
            - 1.1.1.1/24
```