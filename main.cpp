// main.cpp
// Mini-App de Citas/Turnos (Appointments)
// Requisitos: hashing de contrasenas (SHA-256), CRUD, roles, logs, etc.
// NO usa OpenSSL ni librerias externas: todo es C++ estandar.
//
// Compilar con g++:
//   g++ main.cpp -std=c++17 -o appointments.exe
//
// Al ejecutar:
//   .\appointments.exe   (en Windows)

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <regex>
#include <fstream>
#include <chrono>
#include <ctime>
#include <limits>
#include <algorithm>
#include <cstring>   // memset, strncpy, strcpy
#include <cstdint>

using namespace std;

// -----------------------------------------------------------------------------
//  SHA-256 IMPLEMENTACION SIMPLE (SIN LIBRERIAS EXTERNAS)
// -----------------------------------------------------------------------------

namespace SimpleSHA256 {

    inline uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }

    inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (~x & z);
    }

    inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    inline uint32_t big_sigma0(uint32_t x) {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }

    inline uint32_t big_sigma1(uint32_t x) {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }

    inline uint32_t small_sigma0(uint32_t x) {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }

    inline uint32_t small_sigma1(uint32_t x) {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }

    static const uint32_t K[64] = {
        0x428a2f98UL,0x71374491UL,0xb5c0fbcfUL,0xe9b5dba5UL,
        0x3956c25bUL,0x59f111f1UL,0x923f82a4UL,0xab1c5ed5UL,
        0xd807aa98UL,0x12835b01UL,0x243185beUL,0x550c7dc3UL,
        0x72be5d74UL,0x80deb1feUL,0x9bdc06a7UL,0xc19bf174UL,
        0xe49b69c1UL,0xefbe4786UL,0x0fc19dc6UL,0x240ca1ccUL,
        0x2de92c6fUL,0x4a7484aaUL,0x5cb0a9dcUL,0x76f988daUL,
        0x983e5152UL,0xa831c66dUL,0xb00327c8UL,0xbf597fc7UL,
        0xc6e00bf3UL,0xd5a79147UL,0x06ca6351UL,0x14292967UL,
        0x27b70a85UL,0x2e1b2138UL,0x4d2c6dfcUL,0x53380d13UL,
        0x650a7354UL,0x766a0abbUL,0x81c2c92eUL,0x92722c85UL,
        0xa2bfe8a1UL,0xa81a664bUL,0xc24b8b70UL,0xc76c51a3UL,
        0xd192e819UL,0xd6990624UL,0xf40e3585UL,0x106aa070UL,
        0x19a4c116UL,0x1e376c08UL,0x2748774cUL,0x34b0bcb5UL,
        0x391c0cb3UL,0x4ed8aa4aUL,0x5b9cca4fUL,0x682e6ff3UL,
        0x748f82eeUL,0x78a5636fUL,0x84c87814UL,0x8cc70208UL,
        0x90befffaUL,0xa4506cebUL,0xbef9a3f7UL,0xc67178f2UL
    };

    string sha256_hex(const string &input) {
        vector<uint8_t> msg(input.begin(), input.end());
        uint64_t bit_len = static_cast<uint64_t>(msg.size()) * 8;

        msg.push_back(0x80);
        while ((msg.size() % 64) != 56) {
            msg.push_back(0x00);
        }

        for (int i = 7; i >= 0; --i) {
            msg.push_back(static_cast<uint8_t>((bit_len >> (i * 8)) & 0xFF));
        }

        uint32_t H[8] = {
            0x6a09e667UL,
            0xbb67ae85UL,
            0x3c6ef372UL,
            0xa54ff53aUL,
            0x510e527fUL,
            0x9b05688cUL,
            0x1f83d9abUL,
            0x5be0cd19UL
        };

        uint32_t w[64];
        for (size_t offset = 0; offset < msg.size(); offset += 64) {
            for (int i = 0; i < 16; ++i) {
                size_t idx = offset + i * 4;
                w[i]  = (uint32_t)msg[idx]     << 24;
                w[i] |= (uint32_t)msg[idx + 1] << 16;
                w[i] |= (uint32_t)msg[idx + 2] << 8;
                w[i] |= (uint32_t)msg[idx + 3];
            }
            for (int i = 16; i < 64; ++i) {
                w[i] = small_sigma1(w[i-2]) + w[i-7] + small_sigma0(w[i-15]) + w[i-16];
            }

            uint32_t a = H[0];
            uint32_t b = H[1];
            uint32_t c = H[2];
            uint32_t d = H[3];
            uint32_t e = H[4];
            uint32_t f = H[5];
            uint32_t g = H[6];
            uint32_t h = H[7];

            for (int i = 0; i < 64; ++i) {
                uint32_t t1 = h + big_sigma1(e) + ch(e,f,g) + K[i] + w[i];
                uint32_t t2 = big_sigma0(a) + maj(a,b,c);
                h = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
            }

            H[0] += a;
            H[1] += b;
            H[2] += c;
            H[3] += d;
            H[4] += e;
            H[5] += f;
            H[6] += g;
            H[7] += h;
        }

        stringstream ss;
        ss << hex << setfill('0');
        for (int i = 0; i < 8; ++i) {
            ss << setw(8) << H[i];
        }
        return ss.str();
    }

} // namespace SimpleSHA256

string sha256_hex(const string &input) {
    return SimpleSHA256::sha256_hex(input);
}

// -----------------------------------------------------------------------------
//  CONFIGURACION / UTILIDADES GENERALES
// -----------------------------------------------------------------------------

const string USERS_FILE = "users.txt";        // username|sha256hex|role
const string APPTS_FILE = "appointments.txt"; // id|client_username|start_epoch|duration_min|status
const string AUDIT_FILE = "audit.log";

const size_t MAX_USERNAME_LEN = 30;
const size_t MAX_PASSWORD_LEN = 128;
const int    MIN_PASS_LEN     = 6;
const size_t MAX_STATUS_LEN   = 32;

string current_time_str(){
    auto now = chrono::system_clock::now();
    time_t t = chrono::system_clock::to_time_t(now);
    char buf[64];
    strftime(buf, sizeof(buf), "%F %T", localtime(&t));
    return string(buf);
}

time_t parse_datetime_local(const string &s){
    if(s.size() < 16) return -1;
    struct tm tm{};
    try{
        tm.tm_year = stoi(s.substr(0,4)) - 1900;
        tm.tm_mon  = stoi(s.substr(5,2)) - 1;
        tm.tm_mday = stoi(s.substr(8,2));
        tm.tm_hour = stoi(s.substr(11,2));
        tm.tm_min  = stoi(s.substr(14,2));
        tm.tm_sec  = 0;
        tm.tm_isdst = -1;
        return mktime(&tm);
    } catch(...){
        return -1;
    }
}

string datetime_from_epoch(time_t t){
    char buf[64];
    struct tm *tm = localtime(&t);
    strftime(buf, sizeof(buf), "%F %R", tm);
    return string(buf);
}

string sanitize_for_csv(const string &s){
    string out;
    for(char c: s){
        if(c == '\n' || c == '\r' || c == '|') out.push_back(' ');
        else out.push_back(c);
    }
    return out;
}

bool valid_username(const string &u){
    if(u.empty() || u.size() > MAX_USERNAME_LEN) return false;
    static regex re("^[A-Za-z0-9_.-]+$");
    return regex_match(u, re);
}

bool valid_password(const string &p){
    if(p.empty() || p.size() > MAX_PASSWORD_LEN) return false;
    return p.size() >= MIN_PASS_LEN;
}

bool valid_status(const string &s){
    if(s.empty() || s.size() > MAX_STATUS_LEN) return false;
    static regex re("^[A-Za-z0-9_ -]+$");
    return regex_match(s, re);
}

// -----------------------------------------------------------------------------
//  LOG DE AUDITORIA
// -----------------------------------------------------------------------------

void audit_log(const string &user, const string &action, const string &details = ""){
    ofstream f(AUDIT_FILE, ios::app);
    if(!f.is_open()) return;
    string d = details;
    if(d.size() > 500) d = d.substr(0,500) + "...";
    f << current_time_str()
      << " | user:"   << (user.empty() ? "anonymous" : user)
      << " | action:" << action;
    if(!d.empty()){
        f << " | details:" << sanitize_for_csv(d);
    }
    f << "\n";
    f.close();
}

// -----------------------------------------------------------------------------
//  USUARIOS
// -----------------------------------------------------------------------------

struct User {
    string username;
    string passhash;
    string role; // "client" o "staff"
};

vector<User> load_users(){
    vector<User> res;
    ifstream f(USERS_FILE);
    if(!f.is_open()){
        ofstream create(USERS_FILE, ios::app); create.close();
        return res;
    }
    string line;
    while(getline(f, line)){
        if(line.empty()) continue;
        stringstream ss(line);
        string u,h,r;
        if(!getline(ss,u,'|')) continue;
        if(!getline(ss,h,'|')) continue;
        if(!getline(ss,r)) r="";
        res.push_back({u,h,r});
    }
    f.close();
    return res;
}

bool save_user(const User &user){
    ofstream f(USERS_FILE, ios::app);
    if(!f.is_open()) return false;
    f << sanitize_for_csv(user.username) << "|"
      << user.passhash << "|"
      << user.role << "\n";
    f.close();
    return true;
}

User* find_user(vector<User> &users, const string &username){
    for(auto &u: users){
        if(u.username == username) return &u;
    }
    return nullptr;
}

// -----------------------------------------------------------------------------
//  CITAS / TURNOS
// -----------------------------------------------------------------------------

struct Appt {
    long long id;
    string    client;
    time_t    start_epoch;
    int       duration_min;
    string    status; // scheduled, canceled, attended, no_show
};

vector<Appt> load_appts(){
    vector<Appt> res;
    ifstream f(APPTS_FILE);
    if(!f.is_open()){
        ofstream create(APPTS_FILE, ios::app); create.close();
        return res;
    }
    string line;
    while(getline(f, line)){
        if(line.empty()) continue;
        stringstream ss(line);
        string id_s, client, start_s, dur_s, status;
        if(!getline(ss,id_s,'|')) continue;
        if(!getline(ss,client,'|')) continue;
        if(!getline(ss,start_s,'|')) continue;
        if(!getline(ss,dur_s,'|')) continue;
        if(!getline(ss,status)) status = "";
        try{
            Appt a;
            a.id          = stoll(id_s);
            a.client      = client;
            a.start_epoch = (time_t)stoll(start_s);
            a.duration_min= stoi(dur_s);
            a.status      = status;
            res.push_back(a);
        } catch(...){
            // linea corrupta
        }
    }
    f.close();
    return res;
}

bool save_appts_all(const vector<Appt> &appts){
    ofstream f(APPTS_FILE, ios::trunc);
    if(!f.is_open()) return false;
    for(const auto &a : appts){
        f << a.id << "|"
          << sanitize_for_csv(a.client) << "|"
          << (long long)a.start_epoch << "|"
          << a.duration_min << "|"
          << sanitize_for_csv(a.status) << "\n";
    }
    f.close();
    return true;
}

long long next_appt_id(const vector<Appt> &appts){
    long long mx = 0;
    for(const auto &a : appts){
        if(a.id > mx) mx = a.id;
    }
    return mx + 1;
}

bool has_overlap_for_client(const vector<Appt> &appts,
                            const string &client,
                            time_t new_start,
                            int duration,
                            long long ignore_id = -1)
{
    time_t new_end = new_start + duration * 60;
    for(const auto &a : appts){
        if(a.id == ignore_id) continue;
        if(a.client != client) continue;
        if(a.status == "canceled") continue;
        time_t s = a.start_epoch;
        time_t e = a.start_epoch + a.duration_min * 60;
        if(!(new_end <= s || new_start >= e)){
            return true;
        }
    }
    return false;
}

// -----------------------------------------------------------------------------
//  FUNCIONES DE INTERFAZ
// -----------------------------------------------------------------------------

void register_user(){
    cout << "=== Registro de usuario ===\n";
    string username, password, role;

    cout << "Nombre de usuario (solo letras, digitos, _ . -) max "
         << MAX_USERNAME_LEN << ": ";
    getline(cin, username);

    if(!valid_username(username)){
        cout << "Nombre invalido.\n";
        return;
    }

    vector<User> users = load_users();
    if(find_user(users, username)){
        cout << "Usuario ya existe.\n";
        return;
    }

    cout << "Contrasena (min " << MIN_PASS_LEN << " caracteres): ";
    getline(cin, password);

    if(!valid_password(password)){
        cout << "Contrasena invalida.\n";
        return;
    }

    cout << "Rol ('client' o 'staff'): ";
    getline(cin, role);
    if(role != "client" && role != "staff"){
        cout << "Rol invalido.\n";
        return;
    }

    string hash = sha256_hex(password);
    User u{username, hash, role};

    if(!save_user(u)){
        cout << "Error guardando usuario.\n";
        return;
    }

    audit_log(username, "register", "role=" + role);
    cout << "Usuario registrado con exito.\n";
}

pair<bool, User> login_user(){
    cout << "=== Login ===\n";
    string username, password;
    cout << "Usuario: ";
    getline(cin, username);
    cout << "Contrasena: ";
    getline(cin, password);

    vector<User> users = load_users();
    User* u = find_user(users, username);
    if(!u){
        cout << "Usuario/contrasena invalidos.\n";
        return {false, User()};
    }
    string hash = sha256_hex(password);
    if(hash != u->passhash){
        cout << "Usuario/contrasena invalidos.\n";
        return {false, User()};
    }
    audit_log(username, "login", "success");
    cout << "Bienvenido, " << username << " (" << u->role << ")\n";
    return {true, *u};
}

void list_appts(const User &actor, const string &filter_client = ""){
    vector<Appt> appts = load_appts();
    cout << "=== Lista de citas ===\n";
    cout << left
         << setw(6)  << "ID"
         << setw(20) << "Client"
         << setw(20) << "Start"
         << setw(8)  << "Dur"
         << setw(12) << "Status"
         << "\n";
    for(const auto &a : appts){
        if(actor.role == "client" && a.client != actor.username) continue;
        if(!filter_client.empty() && a.client != filter_client) continue;
        cout << left
             << setw(6)  << a.id
             << setw(20) << a.client
             << setw(20) << datetime_from_epoch(a.start_epoch)
             << setw(8)  << a.duration_min
             << setw(12) << a.status
             << "\n";
    }
}

Appt* find_appt(vector<Appt> &appts, long long id){
    for(auto &a : appts){
        if(a.id == id) return &a;
    }
    return nullptr;
}

void create_appt(const string &actor_user, const User &actor, const string &client_username){
    vector<Appt> appts = load_appts();
    cout << "=== Crear cita ===\n";

    string dt_s;
    cout << "Fecha y hora (YYYY-MM-DD HH:MM): ";
    getline(cin, dt_s);
    time_t start = parse_datetime_local(dt_s);
    if(start == -1){
        cout << "Formato de fecha invalido.\n";
        return;
    }

    string dur_s;
    cout << "Duracion en minutos: ";
    getline(cin, dur_s);
    int dur = 0;
    try{
        dur = stoi(dur_s);
    } catch(...){
        cout << "Duracion invalida.\n";
        return;
    }
    if(dur <= 0 || dur > 24*60){
        cout << "Duracion invalida.\n";
        return;
    }

    string client = client_username;
    if(actor.role == "client" && actor.username != client){
        cout << "No tienes permiso para crear cita para otro cliente.\n";
        return;
    }

    time_t now = chrono::system_clock::to_time_t(chrono::system_clock::now());
    if(actor.role == "client" && start <= now){
        cout << "Los clientes solo pueden crear citas en el futuro.\n";
        return;
    }

    if(has_overlap_for_client(appts, client, start, dur)){
        cout << "La nueva cita solapa con otra existente.\n";
        return;
    }

    Appt a;
    a.id           = next_appt_id(appts);
    a.client       = client;
    a.start_epoch  = start;
    a.duration_min = dur;
    a.status       = "scheduled";

    appts.push_back(a);
    if(!save_appts_all(appts)){
        cout << "Error guardando cita.\n";
        return;
    }

    audit_log(actor_user, "create_appt",
              "id=" + to_string(a.id) + " client=" + client +
              " start=" + datetime_from_epoch(a.start_epoch));
    cout << "Cita creada (id=" << a.id << ").\n";
}

void reprogram_appt(const string &actor_user, const User &actor){
    vector<Appt> appts = load_appts();
    cout << "=== Reprogramar cita ===\n";
    string id_s;
    cout << "ID de la cita: ";
    getline(cin, id_s);
    long long id = 0;
    try{
        id = stoll(id_s);
    } catch(...){
        cout << "ID invalido.\n";
        return;
    }

    Appt* a = find_appt(appts, id);
    if(!a){
        cout << "Cita no encontrada.\n";
        return;
    }

    if(actor.role == "client" && a->client != actor.username){
        cout << "No tienes permiso.\n";
        return;
    }

    time_t now = chrono::system_clock::to_time_t(chrono::system_clock::now());
    if(actor.role == "client"){
        double hours_left = difftime(a->start_epoch, now) / 3600.0;
        if(hours_left < 24.0){
            cout << "No puedes reprogramar: faltan menos de 24 horas.\n";
            return;
        }
    }

    string dt_s;
    cout << "Nueva fecha y hora (YYYY-MM-DD HH:MM): ";
    getline(cin, dt_s);
    time_t new_start = parse_datetime_local(dt_s);
    if(new_start == -1){
        cout << "Formato invalido.\n";
        return;
    }

    string dur_s;
    cout << "Nueva duracion (minutos): ";
    getline(cin, dur_s);
    int dur = 0;
    try{
        dur = stoi(dur_s);
    } catch(...){
        cout << "Duracion invalida.\n";
        return;
    }
    if(dur <= 0 || dur > 24*60){
        cout << "Duracion invalida.\n";
        return;
    }

    if(actor.role == "client" && new_start <= now){
        cout << "La nueva fecha debe ser futura.\n";
        return;
    }

    if(has_overlap_for_client(appts, a->client, new_start, dur, a->id)){
        cout << "La nueva fecha solapa con otra cita.\n";
        return;
    }

    time_t old_start = a->start_epoch;
    a->start_epoch   = new_start;
    a->duration_min  = dur;
    a->status        = "scheduled";

    if(!save_appts_all(appts)){
        cout << "Error guardando.\n";
        return;
    }

    audit_log(actor_user, "reprogram_appt",
              "id=" + to_string(a->id) +
              " old=" + datetime_from_epoch(old_start) +
              " new=" + datetime_from_epoch(new_start));
    cout << "Cita reprogramada.\n";
}

void delete_appt(const string &actor_user, const User &actor){
    vector<Appt> appts = load_appts();
    cout << "=== Cancelar cita ===\n";
    string id_s;
    cout << "ID: ";
    getline(cin, id_s);
    long long id = 0;
    try{
        id = stoll(id_s);
    } catch(...){
        cout << "ID invalido.\n";
        return;
    }

    auto it = find_if(appts.begin(), appts.end(),
                      [id](const Appt &a){ return a.id == id; });
    if(it == appts.end()){
        cout << "Cita no encontrada.\n";
        return;
    }

    if(actor.role == "client" && it->client != actor.username){
        cout << "No tienes permiso.\n";
        return;
    }

    it->status = "canceled";
    if(!save_appts_all(appts)){
        cout << "Error guardando.\n";
        return;
    }
    audit_log(actor_user, "delete_appt", "id=" + to_string(id));
    cout << "Cita cancelada.\n";
}

void mark_attendance(const string &actor_user, const User &actor){
    if(actor.role != "staff"){
        cout << "Solo staff puede marcar asistencia.\n";
        return;
    }
    vector<Appt> appts = load_appts();
    cout << "=== Marcar asistencia ===\n";
    string id_s;
    cout << "ID: ";
    getline(cin, id_s);
    long long id = 0;
    try{
        id = stoll(id_s);
    } catch(...){
        cout << "ID invalido.\n";
        return;
    }
    Appt* a = find_appt(appts, id);
    if(!a){
        cout << "Cita no encontrada.\n";
        return;
    }
    cout << "Opciones: 1=attended, 2=no_show\nElige: ";
    string c; getline(cin, c);
    if(c == "1")      a->status = "attended";
    else if(c == "2") a->status = "no_show";
    else{
        cout << "Opcion invalida.\n";
        return;
    }
    if(!save_appts_all(appts)){
        cout << "Error guardando.\n";
        return;
    }
    audit_log(actor_user, "mark_attendance",
              "id=" + to_string(a->id) + " status=" + a->status);
    cout << "Asistencia registrada.\n";
}

void show_audit(const User &actor){
    if(actor.role != "staff"){
        cout << "Solo staff puede ver el log.\n";
        return;
    }
    ifstream f(AUDIT_FILE);
    if(!f.is_open()){
        cout << "No hay archivo de auditoria.\n";
        return;
    }
    cout << "=== Audit log ===\n";
    string line;
    int count = 0;
    while(getline(f, line) && count < 500){
        cout << line << "\n";
        ++count;
    }
    if(count == 500) cout << "... (truncado)\n";
    f.close();
}

// -----------------------------------------------------------------------------
//  DEMOS de buffer overflow (vulnerable vs fixed)
// -----------------------------------------------------------------------------

void demo_buffer_overflow_vulnerable(){
    cout << "DEMO VULNERABLE: uso de strcpy sin control (NO usar en codigo real).\n";
    char src[512];
    char dest[16];
    cout << "Ingresa texto (si pones >16 chars se puede corromper memoria): ";
    string s;
    getline(cin, s);
    memset(src, 0, sizeof(src));
    strncpy(src, s.c_str(), sizeof(src) - 1);
    // Zona vulnerable a proposito
    strcpy(dest, src); // PELIGROSO: puede causar overflow
    cout << "dest (inseguro): " << dest << "\n";
    audit_log("", "demo_vuln_overflow", "strcpy usado (demo)");
}

void demo_buffer_overflow_fixed(){
    cout << "DEMO CORREGIDA: uso de strncpy y validacion de tamano.\n";
    char dest[16];
    string s;
    cout << "Ingresa texto: ";
    getline(cin, s);
    memset(dest, 0, sizeof(dest));
    if(s.size() >= sizeof(dest)){
        cout << "Input demasiado largo, se truncara de forma segura.\n";
    }
    strncpy(dest, s.c_str(), sizeof(dest) - 1);
    cout << "dest (seguro): " << dest << "\n";
    audit_log("", "demo_fixed_overflow", "strncpy usado (demo)");
}

// -----------------------------------------------------------------------------
//  LOOP DE SESION (MENU POR ROL)
// -----------------------------------------------------------------------------

void session_loop(const User &user){
    string actor = user.username;
    while(true){
        cout << "\n=== MENU (" << user.role << ") ===\n";
        cout << "1) Crear cita\n";
        cout << "2) Listar mis citas\n";
        cout << "3) Reprogramar cita\n";
        cout << "4) Cancelar cita\n";
        cout << "5) Demostraciones (buffer overflow)\n";
        cout << "6) Logout\n";
        if(user.role == "staff"){
            cout << "7) Listar todas las citas (staff)\n";
            cout << "8) Crear cita para cliente (staff)\n";
            cout << "9) Marcar asistencia\n";
            cout << "10) Ver audit log\n";
        }
        cout << "Opcion: ";
        string opt;
        getline(cin, opt);

        if(opt == "1"){
            create_appt(actor, user, user.username);
        } else if(opt == "2"){
            list_appts(user);
        } else if(opt == "3"){
            reprogram_appt(actor, user);
        } else if(opt == "4"){
            delete_appt(actor, user);
        } else if(opt == "5"){
            cout << "a) vulnerable\nb) fixed\nElige: ";
            string c; getline(cin, c);
            if(c == "a") demo_buffer_overflow_vulnerable();
            else         demo_buffer_overflow_fixed();
        } else if(opt == "6"){
            audit_log(actor, "logout");
            cout << "Logout.\n";
            break;
        } else if(user.role == "staff" && opt == "7"){
            list_appts(user, "");
        } else if(user.role == "staff" && opt == "8"){
            cout << "Cliente (username): ";
            string cu; getline(cin, cu);
            vector<User> users = load_users();
            User* uu = find_user(users, cu);
            if(!uu){
                cout << "Cliente no encontrado.\n";
            } else {
                create_appt(actor, user, cu);
            }
        } else if(user.role == "staff" && opt == "9"){
            mark_attendance(actor, user);
        } else if(user.role == "staff" && opt == "10"){
            show_audit(user);
        } else {
            cout << "Opcion invalida.\n";
        }
    }
}

// -----------------------------------------------------------------------------
//  MAIN
// -----------------------------------------------------------------------------

int main(){
    // Dejamos sync_with_stdio en true por compatibilidad con tu entorno

    cout << "=== Mini-App de Citas/Turnos (Appointments) ===\n";

    {
        ofstream f1(USERS_FILE, ios::app); f1.close();
        ofstream f2(APPTS_FILE, ios::app); f2.close();
        ofstream f3(AUDIT_FILE, ios::app); f3.close();
    }

    while(true){
        cout << "\n1) Register\n";
        cout << "2) Login\n";
        cout << "3) Salir\n";
        cout << "Elige: ";
        string cmd;
        getline(cin, cmd);

        if(cmd == "1"){
            register_user();
        } else if(cmd == "2"){
            auto res = login_user();
            if(res.first){
                session_loop(res.second);
            }
        } else if(cmd == "3"){
            cout << "Bye.\n";
            break;
        } else {
            cout << "Opcion invalida.\n";
        }
    }

    return 0;
}