# dckesc

Dckesc - это веб-приложение для анализа безопасности Docker-контейнеров и образов. Проект предоставляет инструменты для сканирования контейнеров и образов, анализа конфигураций и генерации отчетов.
Наличие api позволяет эффективно внедрять инструмент в ci/cd папйлайны и процессы безопасной разработки.


## Архитектура проекта
Основные компоненты:

### 1. Веб-приложение 
```
Основной интерфейс пользователя
API для взаимодействия с сервисами
Управление пользователями и авторизация
```

### 2. База данных 
```
Хранение пользовательских данных
Хранение результатов сканирования
Хранение конфигураций
```

### 3. Сканирующая система
```
Анализ Docker-контейнеров
Сканирование образов
Сканирование docker-compose файлов
```

### 4. Docker registry
```
Хранение образов, для последующего сканирования
```

## Файловая структура проекта

```
prod/
├── web/                # Веб-приложение
│   ├── app.py          # Основной файл приложения
│   ├── templates/      # HTML шаблоны
│   ├── static/         # Статические файлы
│   └── stuff_scripts/  # Шаблоны скриптов для сканирования
├── dckesc/             # Сканирующая система
├── .env/               # Перменные окружения с учётными данными от сервисов
└── control.py/         # Скрипт, автоматизирующий развёртывние приложения
```

## Эндпоинты API

### /docker-compose/upload

**Описание**: Эндпоинт для загрузки и анализа docker-compose файлов.

**Метод**: POST

**Параметры запроса**: file (multipart/form-data): YAML файл docker-compose

**Ответ**:

```json
{
    "issues": [
        {
            "severity": "string", // "Critical", "High", "Medium", "Low"
            "title": "string",
            "description": "string",
            "recommendation": "string"
        }
    ],
    "recommendations": [
        {
            "title": "string",
            "description": "string"
        }
    ],
    "critical_count": number,
    "high_count": number,
    "medium_count": number,
    "low_count": number
}
```
**Коды ответа**:

```
- 200: Успешный анализ
- 400: Ошибка в формате файла или отсутствие файла
- 500: Внутренняя ошибка сервера
```

Пример использования:

```bash
curl -X POST -F "file=@docker-compose.yml" http://your_host:1703/docker-compose/upload
```


### /api/image-scan/create

**Описание**: Эндпоинт для создания сканирования Docker-образа.

**Метод**: POST

**Параметры запроса**:

```
image (string): Имя образа для сканирования
registry (string): registry образа
registry_name (string): Уникальное имя для registry
owner (string): Username владельца / Public
username (string, опционально): Имя пользователя для доступа к registry
password (string, опционально): Пароль для доступа к registry
```

**Ответ**:

- 200: "Scan started"
- 400: Ошибка в параметрах запроса
- 500: Внутренняя ошибка сервера

**Пример использования**:

```bash
curl -X POST \
  -d "image=nginx:latest" \
  -d "registry=docker.io" \
  -d "registry_name=nginx-scan" \
  -d "owner=user1" \
  http://your_host:1703/api/image-scan/create
```

### /scan/<int:scan_id>/pdf (Auth-required)

**Описание**: Генерация PDF-отчета по результатам сканирования.

**Метод**: GET

**Параметры пути**: scan_id (integer): ID скана

**Ответ**:

- PDF файл с отчетом
- Имя файла: scan_report_{scan_id}_{timestamp}.pdf

**Коды ответа**:

- 200: Успешная генерация PDF
- 403: Отказано в доступе
- 404: Скан не найден
- 500: Ошибка генерации PDF

**Структура PDF-отчета**:

```
- Заголовок отчета
- Информация о скане:
- ID скана
- Имя скана
- Режим сканирования
- Автор скана
- Дата сканирования
- Дата генерации отчета
- Результаты сканирования для каждого контейнера:
- ID контейнера
- Найденные уязвимости
- Статус уязвимостей
- Детали уязвимостей
```

**Пример использования**:

```bash
curl -X GET http://yout_host:1703/scan/123/pdf --output report.pdf -H "Cookie: session=*"

```
### /api/ready

**Описание**: Эндпоинт для инициации сканирования.

**Метод**: POST

**Параметры запроса**:

```
uuid (string): Уникальный идентификатор скана используемый для контроля доступа
scan_id (string): ID скана
```

**Ответ**:

- 200: "Scanning started"
- 400: Отсутствуют обязательные параметры
- 404: Неверный ID скана или UUID
- 500: Ошибка запуска сервиса сканирования

**Пример использования**:

```bash
curl -X POST \
  -d "uuid=550e8400-e29b-41d4-a716-446655440000" \
  -d "scan_id=123" \
  http://your_host:1703/api/ready
```



## Руководство пользователя 

1. Начало работы
2. Управление сканами
3. Анализ Docker-образов
4. Анализ docker-compose
5. Управление пользователями
6. Экспорт отчетов
7. Часто задаваемые вопросы

### Начало работы

**Вход в систему**

Откройте веб-браузер и перейдите по адресу: http://your_host:1703
На странице входа введите свои учетные данные, установленные при запсуке приложения:
- Имя пользователя
- Пароль
Нажмите кнопку "Login"

**Главная страница**

После успешного входа вы увидите:
- Общую статистику сканирований
- Последние выполненные сканы
- Быстрые действия для создания новых сканов
- Управление сканами
- Создание нового скана

**Сканирование контейнеров**

1. Нажмите кнопку "Создать скан" на главной странице
2. Выберите тип сканирования:
    - Blue team сканирование: тестирование защищённости одного и более контейнеров с хоста
    - Red team сканирование: тестирование защищённости одного контейнера изнутри
3. Заполните параметры сканирования:
    - Название сканирования
    - Тип сканирования (разовое/периодическое) *только для Blue team
    - ID контейнеров для сканирования *только для Blue team
4. Нажмите "Создать"

**Просмотр результатов сканирования**

1. Перейдите в раздел "Мои сканы"
2. Выберите интересующий вас скан
В деталях скана вы увидите:
    - Общую информацию о скане
    - Результаты проверки каждого контейнера
    - Найденные уязвимости

**Поделиться  результатами**

1. На главной странице нажмите share 
2. Выберите пользователя из списка
3. Подтвердите действие

**Анализ Docker-образов**

1. Перейдите в раздел "Сканирование образов"
2. Выберите способ сканирования:
    - Автоматический: сканирование контейнеров из registry 
    - Скриптовый: сканирвоание через загружаемый скрипт, загружаешь выбранные образы в локальный registry
3. Укажите параметры:
    - Образы для сканирования
    - Registry
    - Логин/Пароль для registry (при необходимости)
    - Публичность результатов
4. Нажмите "Начать сканирование"

**Просмотр результатов**

1. Перейдите в раздел "Сканы образов"
2. Выберите интересующий вас скан
В деталях вы увидите:
    - Информацию об образе
    - Найденные уязвимости
    - Рекомендации по обновлению

**Анализ docker-compose**

1. Перейдите в раздел "Анализ docker-compose"
2. Нажмите "Выбрать файл"
3. Выберите ваш docker-compose.yml файл
4. Нажмите "Загрузить"
После загрузки вы увидите:
    - Критические проблемы безопасности
    - Предупреждения
    - Рекомендации по улучшению
    - Статистику по типам проблем

**Генерация PDF-отчета**
1. Откройте детали скана
2. Нажмите кнопку "Экспорт в PDF"
PDF-отчет содержит:
    - Информацию о скане
    - Результаты проверки каждого контейнера
    - Детали уязвимостей

### Часто задаваемые вопросы

**Общие вопросы**

Q: Как часто нужно выполнять сканирование?
A: Рекомендуется:
- Разовое сканирование при создании новых контейнеров
- Периодическое сканирование 
- Сканирование после обновления образов

Q: Что делать при обнаружении уязвимостей?
A: Рекомендуемый порядок действий:
- Оценить критичность уязвимости
- Следовать рекомендациям в отчете
- Обновить образы или конфигурацию
- Выполнить повторное сканирование

Технические вопросы
Q: Какой максимальный размер файла docker-compose можно загрузить?
A: Максимальный размер зависит от настроек сервера, по умолчанию до 10MB.

Q: Как долго выполняется сканирование?
A: В среднем сканирование занимат от 5 до 30 минут.
Важно понимать, что время сканирования зависит от:
- Размера образа
- Количества проверяемых контейнеров
- Скорости интернет соединения

**Безопасность**

Q: Как защищены мои данные?
A: Система обеспечивает:
- Шифрование паролей
- Защиту от несанкционированного доступа
- Безопасное хранение результатов

Q: Кто имеет доступ к результатам сканирования?
A: Доступ имеют:
- Создатель скана
- Пользователи, которым явно предоставлен доступ
- Все пользователи, если при создание была включена соответсвующая настройка


### Поддержка

Получение помощи
Если у вас возникли проблемы:
- Проверьте раздел FAQ
- Обратитесь к администратору системы
- Напишите на почту redacted, или создайте issue