Сборка и запуск 
git clone 
cd hickory_bunker
cargo build --release

sudo ./target/release/hickory_bunker

Переключение между режимами оффлайн и онлайн 

curl -X POST http://127.0.0.1:8080/mode \
  -H "Content-Type: application/json" \
  -d '{"offline": true}'

  curl -X POST http://127.0.0.1:8080/mode \
  -H "Content-Type: application/json" \
  -d '{"offline": false}'

  "Заморозка" отдельной зоны 
  
  curl -X POST http://127.0.0.1:8080/freeze \
  -H "Content-Type: application/json" \
  -d '{"zone": "example.com."}'

  Добавить А-запись вручную

  curl -X POST http://127.0.0.1:8080/add_record \
  -H "Content-Type: application/json" \
  -d '{"name": "test.example.com", "ip": "192.168.1.1"}'

  
