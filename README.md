# honeypot

Motor de detección de intrusiones sobre flujos de eventos, con las estructuras de
agregación intercambiables entre una versión exacta y otra probabilística.

Los datos no son sintéticos ni de un repositorio público: salen de un honeypot SSH
propio que lleva capturando ataques reales desde el 14 de septiembre de 2026.

---

## El resultado

Para mantener el ranking de atacantes, **Space-Saving ocupa el 1,2 % de la memoria
del mapa exacto y acierta el 100 %**: 144 KB fijos frente a 12,6 MB con medio millón
de claves.

Y el resultado que no se suele contar: **para la detección de fuerza bruta,
Count-Min Sketch pierde**. Necesita entre 2,7 y 5,3 veces *más* memoria que la
estructura exacta para mantener las falsas alarmas por debajo del 5 %. El motivo
está en la sección de resultados, y no es un fallo de implementación.

---

## Qué hace

```
  Internet ──▶ honeypot Cowrie ──▶ cowrie.json
                                        │
                                        ▼
                                 CowrieNormalizer ──▶ diccionarios (texto → entero)
                                        │
                                        ▼
                                   EventStore              5 arrays primitivos
                                        │
                                        ▼
                                    Replayer ──▶ PartitionedEngine
                                                      │  hash(IP) % N
                                          ┌───────────┼───────────┐
                                        Hilo 0      Hilo 1      Hilo N
                                          │           │           │
                                      DetectionEngine (estado aislado, sin bloqueos)
                                          └───────────┼───────────┘
                                                      ▼
                                                   Alert
```

Tres detecciones, cada una con un tipo de agregación distinto, y cada agregación
con dos implementaciones tras la misma interfaz:

| Detección | Pregunta | Exacta | Probabilística |
|---|---|---|---|
| Fuerza bruta | ¿cuántos intentos lleva esta IP? | `Int2LongOpenHashMap` | Count-Min Sketch |
| Enumeración de usuarios | ¿cuántos usuarios distintos ha probado? | mapa de conjuntos | HyperLogLog |
| Ranking de atacantes | ¿quiénes son los 20 más activos? | mapa + ordenación | Space-Saving |

Ventanas de salto de 60 segundos. Es lo que hace viables a Count-Min Sketch y
HyperLogLog, que no saben borrar elementos: al cerrar la ventana se descarta la
estructura entera.

---

## Los datos

8,4 días de captura continua, del 14 al 23 de septiembre de 2026:

| | |
|---|---|
| Eventos registrados | 216.990 |
| Direcciones IP distintas | 776 |
| Nombres de usuario probados | 1.555 |
| Intentos de acceso fallidos | 42.348 |
| Accesos conseguidos | 639 |
| Órdenes ejecutadas dentro | 761 |
| Descargas de carga útil intentadas | 82 |

Los diez usuarios más probados:

```
root      16.070      deploy       730
ubuntu     2.643      test         599
admin      1.711      claude       310
user         923      user1        306
                      postgres     272
```

El `root` domina, como era de esperar. Que `claude` aparezca en el top-10 sugiere que
las listas de credenciales ya incorporan nombres de herramientas recientes.

### Un ataque real

Sesión completa de un bot, con las direcciones enmascaradas y la clave recortada:

```sh
# 1. Quitar la protección del directorio de claves
cd ~; chattr -ia .ssh; lockr -ia .ssh

# 2. Instalar su propia clave para no necesitar la contraseña otra vez
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EA...[recortada]" > .ssh/authorized_keys

# 3. Averiguar cuánta CPU hay (reconocimiento para minado)
cat /proc/cpuinfo | grep name | wc -l
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2,$3,$4,$5,$6,$7}'
uname -m

# 4. Cambiar la contraseña para echar al dueño
echo -e "user\n[contraseña]\n[contraseña]"|passwd|bash

# 5. Comprobar que no hay nadie mirando
crontab -l
w
```

Otro bot distinto busca datos que vender en lugar de CPU:

```sh
ls -la ~/.local/share/TelegramDesktop/tdata /home/*/.local/share/TelegramDesktop/tdata \
       /dev/ttyGSM* /dev/ttyUSB-mod* /var/spool/sms/*
ps -ef | grep '[Mm]iner'
/ip cloud print
```

Esa última orden es de RouterOS, de MikroTik. El bot la lanza a ciegas por si ha
caído en un router en lugar de en un servidor.

---

## Resultados

Todos son reproducibles con los bancos de pruebas de `engine/src/main/java/.../bench/`.
El tráfico sintético usa una distribución Zipf con exponente **0,8**, calibrado contra
la forma real del tráfico capturado.

### Ranking de atacantes: Space-Saving gana por goleada

Space-Saving con 4.096 contadores, 144 KB fijos, frente al mapa exacto:

| Claves | Exacto | Space-Saving | Memoria | Acierto |
|---:|---:|---:|---:|---:|
| 1.000 | 24 KB | 144 KB | 6,00x | 100 % |
| 5.000 | 96 KB | 144 KB | 1,50x | 100 % |
| 20.000 | 384 KB | 144 KB | **0,375x** | 100 % |
| 100.000 | 1,5 MB | 144 KB | **0,094x** | 100 % |
| 500.000 | 12,6 MB | 144 KB | **0,012x** | 100 % |

El cruce está en unas 5.000 claves. Por encima, el ahorro crece sin límite porque el
sketch no crece: mantiene `k` contadores y punto.

### Fuerza bruta: Count-Min Sketch pierde, y por un buen motivo

Ancho mínimo necesario para mantener las falsas alarmas por debajo del 5 %:

| Claves | Exacto | Count-Min | Memoria | Falsas |
|---:|---:|---:|---:|---:|
| 1.000 | 24 KB | 64 KB | 2,67x | 1,9 % |
| 10.000 | 192 KB | 512 KB | 2,67x | 2,3 % |
| 50.000 | 768 KB | 4,0 MB | 5,33x | 0,7 % |
| 100.000 | 1,5 MB | 8,0 MB | 5,33x | 0,7 % |

Count-Min Sketch acota el error respecto al **total del flujo** (ε·N), no respecto al
valor de cada clave. Con un umbral absoluto bajo —10 intentos— hace falta un ε
diminuto para que las colisiones no crucen el umbral por su cuenta, y eso obliga a un
ancho que crece con el número de claves. Se pierde la ventaja.

**Count-Min Sketch es para claves pesadas, no para umbrales pequeños.** Que es
exactamente el hueco que cubre Space-Saving.

### Cero falsos negativos, verificado

Ninguna alerta perdida en ocho órdenes de magnitud de cardinalidad, en ninguna
configuración de tamaño.

No es casualidad: Count-Min Sketch **solo sobreestima**, porque cada celda contiene lo
que aportó la clave más lo que aportaron las que colisionaron ahí. Con una regla de
umbral eso significa que ningún ataque real puede pasar desapercibido. El sketch puede
inventarse alertas, pero no perder ninguna.

Los bancos de pruebas abortan si alguna vez ocurriera.

### Escalado

2.000.000 de eventos, 50.000 claves, sobre 12 núcleos lógicos:

| Hilos | Eventos/s | Aceleración | Partición más cargada |
|---:|---:|---:|---:|
| 1 | 12,1 M | 1,00x | — |
| 2 | 17,2 M | 1,42x | 51,9 % |
| 4 | 27,5 M | 2,28x | 27,0 % |
| 8 | 28,9 M | 2,40x | 14,3 % |
| 16 | 34,0 M | 2,82x | 8,1 % |

La saturación **no viene del reparto**: con 16 particiones la más cargada se queda en
el 8,1 %, muy cerca del 6,25 % ideal. El cuello de botella es el hilo productor, que
hace el hash y el encolado él solo. Cada trabajador procesa unos 2,1 M eventos/s
cuando en solitario alcanza 12 M, así que están sin trabajo.

---

## Ejecutarlo

Requiere Java 21 y Maven.

```sh
mvn -f engine/pom.xml test
```

Para reproducir los resultados:

```sh
mvn -f engine/pom.xml compile dependency:build-classpath -Dmdep.outputFile=target/cp.txt
java -cp "engine/target/classes:$(cat engine/target/cp.txt)" com.glezpedro.honeypot.bench.TopKSizing 4096
java -cp "engine/target/classes:$(cat engine/target/cp.txt)" com.glezpedro.honeypot.bench.SketchSizing 0.05
java -cp "engine/target/classes:$(cat engine/target/cp.txt)" com.glezpedro.honeypot.bench.ScalingBench
```

En Windows el separador del classpath es `;` en lugar de `:`.

Los guiones de `honeypot/` despliegan el honeypot sobre una máquina Ubuntu: mudan el
SSH de administración a otro puerto, instalan Cowrie sin privilegios, redirigen el 22
hacia él y bloquean sus conexiones salientes.

---

## Decisiones técnicas

**El motor no maneja cadenas de texto.** Las IPs y los usuarios se traducen a enteros
en la entrada. No es por velocidad: si el lado exacto cargara con el coste de los
objetos `String`, la comparación de memoria mediría el envoltorio en lugar de la
estructura de agregación, y el sketch ganaría por el motivo equivocado. Por lo mismo,
el lado exacto usa colecciones primitivas de fastutil y no `HashMap<Integer,Long>`.

**Los eventos se guardan en cinco arrays paralelos, no en objetos.** El evento número
7 son las posiciones 7 de los cinco arrays. Con millones de eventos reproducidos para
medir, una lista de objetos serían millones de asignaciones que el recolector tendría
que perseguir. De ahí que `EventSink` reciba `(almacén, índice)`: no hay objeto que
pasar.

**El umbral se comprueba de forma incremental, no al cerrar la ventana.** Recorrer las
claves al cierre sería lo natural, pero un Count-Min Sketch **no sabe enumerar las
suyas**, y mantener la lista aparte gastaría la memoria que el sketch ahorra. Así que
tras cada suma se consulta esa clave concreta. Esto está codificado en las interfaces:
`CountAggregator` no tiene `keys()` y `CardinalityAggregator` sí. Como efecto
secundario, las alertas salen en el instante en que se cruza el umbral.

**`Alert` es un `record`.** Su `equals` por valor es lo que permite meter las alertas
de ambos modos en dos conjuntos y restarlos para contar las perdidas y las sobrantes.
Con una clase corriente esa resta no significaría nada.

**El modo a tasa fija calcula un instante absoluto por evento.** Dormir un rato tras
cada uno acumula deriva: a los mil eventos se llevan segundos de retraso. Calculando
el instante objetivo desde el arranque, un evento lento no descuadra el ritmo medio.

**Los umbrales están medidos, no supuestos.** Los valores iniciales —20 intentos, 10
usuarios— producían **cero alertas**: el máximo real por IP y minuto resultaron ser 12
intentos y 9 usuarios. Los atacantes no van a ráfagas, van a ritmo constante durante
horas para no disparar limitadores de tasa.

---

## Limitaciones conocidas

**El ranking no particiona.** Con estado repartido por clave, la fuerza bruta y la
enumeración son **idénticas** a la ejecución de un solo hilo. El ranking no: cada
partición emite el suyo. La unión sí contiene siempre el top global —una clave del top
vive en una sola partición y allí está al menos igual de arriba— así que son
candidatos que necesitan una fusión final. Está sin implementar.

**`memoryBytes()` es una estimación razonada** del tamaño de tabla a partir del factor
de carga, no una medida del montón. Suficiente para comparar contra el cálculo
analítico de un sketch, que sí es exacto.

**HyperLogLog necesita un estimador por clave**, y uno denso ocupa cientos de bytes.
Con tráfico real, donde la mayoría de atacantes prueban pocos usuarios, el conjunto
exacto gana. El modo disperso de HLL++ existe precisamente para ese caso y no está
implementado.

**El motor asume eventos en orden temporal.** El registro de Cowrie lo cumple; un
evento retrasado caería en la ventana equivocada.

**Sin panel todavía.** El conmutador exacto/probabilístico en vivo está diseñado pero
no construido.

---

## Datos personales

Las direcciones IP capturadas son datos personales, y las contraseñas que prueban los
bots proceden en su mayoría de filtraciones reales de terceros. Ni unas ni otras se
versionan ni aparecen en este documento: los registros en crudo están excluidos del
repositorio y las direcciones de los ejemplos están enmascaradas.
