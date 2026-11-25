#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <limits>
#include <filesystem>
#include <array>
#include <windows.h>
#include <bcrypt.h>
#include <conio.h>

using namespace std;

struct Produto {
    int codigo;
    string nome;
    string categoria;
    double preco;
    int quantidade;
};

vector<Produto> estoque;
const string ARQUIVO = "dados/produtos.txt";
const string ARQUIVO_USUARIO = "dados/usuario.txt";
const string ARQUIVO_USUARIO_TEMP = "dados/usuario.tmp";
constexpr ULONG ITERACOES_HASH = 200000;

string lerTexto(string mensagem);

string lerSenha(string mensagem) {
    cout << mensagem;
    string senha;

    while (true) {
        int caractere = _getch();

        if (caractere == '\r' || caractere == '\n') {
            cout << "\n";
            return senha;
        }

        if (caractere == 8) {
            if (!senha.empty()) {
                senha.pop_back();
                cout << "\b \b";
            }
            continue;
        }

        if (caractere == 0 || caractere == 224) {
            _getch();
            continue;
        }

        if (caractere >= 32 && caractere <= 126) {
            senha.push_back(static_cast<char>(caractere));
            cout << "*";
        }
    }
}

string converterHex(const UCHAR* bytes, size_t tamanho) {
    stringstream resultado;
    resultado << hex << setfill('0');

    for (size_t i = 0; i < tamanho; i++) {
        resultado << setw(2) << static_cast<int>(bytes[i]);
    }

    return resultado.str();
}

int valorHex(char caractere) {
    if (caractere >= '0' && caractere <= '9') {
        return caractere - '0';
    }
    if (caractere >= 'a' && caractere <= 'f') {
        return caractere - 'a' + 10;
    }
    if (caractere >= 'A' && caractere <= 'F') {
        return caractere - 'A' + 10;
    }
    return -1;
}

bool lerHex(const string& texto, UCHAR* bytes, size_t tamanho) {
    if (texto.size() != tamanho * 2) {
        return false;
    }

    for (size_t i = 0; i < tamanho; i++) {
        int alto = valorHex(texto[i * 2]);
        int baixo = valorHex(texto[i * 2 + 1]);
        if (alto < 0 || baixo < 0) {
            return false;
        }
        bytes[i] = static_cast<UCHAR>((alto << 4) | baixo);
    }

    return true;
}

bool gerarHashSenha(const string& senha, const array<UCHAR, 16>& sal,
                    array<UCHAR, 32>& hash) {
    BCRYPT_ALG_HANDLE algoritmo = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &algoritmo, BCRYPT_SHA256_ALGORITHM, nullptr,
        BCRYPT_ALG_HANDLE_HMAC_FLAG);

    if (!BCRYPT_SUCCESS(status)) {
        cout << "Erro ao iniciar a protecao da senha.\n";
        return false;
    }

    vector<UCHAR> bytesSenha(senha.begin(), senha.end());
    status = BCryptDeriveKeyPBKDF2(
        algoritmo, bytesSenha.data(), static_cast<ULONG>(bytesSenha.size()),
        const_cast<PUCHAR>(sal.data()), static_cast<ULONG>(sal.size()),
        ITERACOES_HASH, hash.data(), static_cast<ULONG>(hash.size()), 0);
    BCryptCloseAlgorithmProvider(algoritmo, 0);

    if (!BCRYPT_SUCCESS(status)) {
        cout << "Erro ao processar a senha.\n";
        return false;
    }

    return true;
}

bool conferirSenha(const string& senha, const array<UCHAR, 16>& sal,
                   const array<UCHAR, 32>& hashSalvo, bool& hashCalculado) {
    array<UCHAR, 32> hashDigitado;
    hashCalculado = false;
    if (!gerarHashSenha(senha, sal, hashDigitado)) {
        return false;
    }
    hashCalculado = true;

    UCHAR diferenca = 0;
    for (size_t i = 0; i < hashSalvo.size(); i++) {
        diferenca |= hashSalvo[i] ^ hashDigitado[i];
    }
    return diferenca == 0;
}

bool carregarCredenciais(string& usuario, array<UCHAR, 16>& sal,
                         array<UCHAR, 32>& hash) {
    ifstream arquivo(ARQUIVO_USUARIO);
    string salHex, hashHex, linhaExtra;

    if (!arquivo || !getline(arquivo, usuario) ||
        !getline(arquivo, salHex) || !getline(arquivo, hashHex) ||
        getline(arquivo, linhaExtra) || usuario.empty() ||
        !lerHex(salHex, sal.data(), sal.size()) ||
        !lerHex(hashHex, hash.data(), hash.size())) {
        cout << "Arquivo de usuario invalido ou inacessivel: "
             << ARQUIVO_USUARIO << "\n";
        return false;
    }

    return true;
}

bool salvarCredenciais(const string& usuario, const array<UCHAR, 16>& sal,
                       const array<UCHAR, 32>& hash) {
    ofstream arquivo(ARQUIVO_USUARIO_TEMP, ios::trunc);
    if (!arquivo) {
        cout << "Erro ao preparar o arquivo da nova senha.\n";
        return false;
    }

    arquivo << usuario << "\n"
            << converterHex(sal.data(), sal.size()) << "\n"
            << converterHex(hash.data(), hash.size()) << "\n";
    arquivo.close();
    if (!arquivo) {
        cout << "Erro ao gravar o arquivo da nova senha.\n";
        return false;
    }

    if (!MoveFileExA(ARQUIVO_USUARIO_TEMP.c_str(), ARQUIVO_USUARIO.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        cout << "Erro ao atualizar a senha. Codigo: "
             << GetLastError() << "\n";
        return false;
    }
    return true;
}

void trocarSenha() {
    string usuario;
    array<UCHAR, 16> salAtual;
    array<UCHAR, 32> hashAtual;

    cout << "\n===== TROCAR SENHA =====\n";
    if (!carregarCredenciais(usuario, salAtual, hashAtual)) {
        return;
    }

    string senhaAtual = lerSenha("Senha atual: ");
    bool hashCalculado;
    bool senhaCorreta = conferirSenha(
        senhaAtual, salAtual, hashAtual, hashCalculado);
    if (!hashCalculado) {
        return;
    }
    if (!senhaCorreta) {
        cout << "Senha atual incorreta.\n";
        return;
    }

    string novaSenha = lerSenha("Nova senha (minimo 8 caracteres): ");
    if (novaSenha.size() < 8) {
        cout << "A senha precisa ter pelo menos 8 caracteres.\n";
        return;
    }

    string confirmacao = lerSenha("Confirme a nova senha: ");
    if (novaSenha != confirmacao) {
        cout << "As senhas nao conferem.\n";
        return;
    }

    array<UCHAR, 16> novoSal;
    array<UCHAR, 32> novoHash;
    NTSTATUS status = BCryptGenRandom(
        nullptr, novoSal.data(), static_cast<ULONG>(novoSal.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status) ||
        !gerarHashSenha(novaSenha, novoSal, novoHash)) {
        cout << "Nao foi possivel gerar a nova senha.\n";
        return;
    }

    if (salvarCredenciais(usuario, novoSal, novoHash)) {
        cout << "Senha alterada com sucesso.\n";
    }
}

bool configurarUsuario() {
    cout << "\n===== CRIAR CONTA DE ACESSO =====\n";
    string usuario = lerTexto("Novo usuario: ");
    if (usuario.empty()) {
        cout << "O usuario nao pode ficar vazio.\n";
        return false;
    }

    string senha = lerSenha("Crie uma senha (minimo 8 caracteres): ");
    if (senha.size() < 8) {
        cout << "A senha precisa ter pelo menos 8 caracteres.\n";
        return false;
    }

    string confirmacao = lerSenha("Confirme a senha: ");
    if (senha != confirmacao) {
        cout << "As senhas nao conferem.\n";
        return false;
    }

    array<UCHAR, 16> sal;
    array<UCHAR, 32> hash;
    NTSTATUS status = BCryptGenRandom(
        nullptr, sal.data(), static_cast<ULONG>(sal.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status) || !gerarHashSenha(senha, sal, hash)) {
        cout << "Nao foi possivel criar a conta.\n";
        return false;
    }

    filesystem::create_directories("dados");
    ofstream arquivo(ARQUIVO_USUARIO);
    if (!arquivo) {
        cout << "Erro ao salvar a conta em " << ARQUIVO_USUARIO << ".\n";
        return false;
    }

    arquivo << usuario << "\n"
            << converterHex(sal.data(), sal.size()) << "\n"
            << converterHex(hash.data(), hash.size()) << "\n";
    if (!arquivo) {
        cout << "Erro ao salvar a conta em " << ARQUIVO_USUARIO << ".\n";
        return false;
    }

    cout << "Conta criada. Acesso liberado.\n";
    return true;
}

bool autenticar() {
    ifstream arquivo(ARQUIVO_USUARIO);
    if (!arquivo) {
        error_code erro;
        bool existe = filesystem::exists(ARQUIVO_USUARIO, erro);
        if (erro || existe) {
            cout << "Nao foi possivel ler " << ARQUIVO_USUARIO << ".\n";
            return false;
        }
        return configurarUsuario();
    }

    string usuarioSalvo;
    array<UCHAR, 16> sal;
    array<UCHAR, 32> hashSalvo;
    if (!carregarCredenciais(usuarioSalvo, sal, hashSalvo)) {
        return false;
    }

    cout << "\n===== LOGIN DO SISTEMA =====\n";
    for (int tentativa = 1; tentativa <= 3; tentativa++) {
        string usuario = lerTexto("Usuario: ");
        string senha = lerSenha("Senha: ");

        bool hashCalculado;
        bool senhaCorreta = conferirSenha(
            senha, sal, hashSalvo, hashCalculado);
        if (!hashCalculado) {
            return false;
        }

        if (usuario == usuarioSalvo && senhaCorreta) {
            cout << "Login realizado com sucesso.\n";
            return true;
        }

        cout << "Usuario ou senha incorretos. Tentativa "
             << tentativa << " de 3.\n";
    }

    cout << "Acesso bloqueado. Reinicie o programa para tentar novamente.\n";
    return false;
}

// Ler numero inteiro com validacao
int lerInteiro(string mensagem) {
    int valor;
    while (true) {
        cout << mensagem;
        if (cin >> valor) {
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            return valor;
        }
        cout << "Valor invalido!\n";
        cin.clear();
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
    }
}

// Ler preco com validacao
double lerPreco(string mensagem) {
    double valor;
    while (true) {
        cout << mensagem;
        if (cin >> valor && valor >= 0) {
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            return valor;
        }
        cout << "Preco invalido!\n";
        cin.clear();
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
    }
}

// Ler texto
string lerTexto(string mensagem) {
    string texto;
    cout << mensagem;
    getline(cin, texto);
    return texto;
}

// Procurar produto pelo codigo
int buscarProduto(int codigo) {
    for (int i = 0; i < (int)estoque.size(); i++) {
        if (estoque[i].codigo == codigo) {
            return i;
        }
    }
    return -1;
}

// Salvar estoque
void salvarEstoque() {
    filesystem::create_directories("dados");
    ofstream arquivo(ARQUIVO);

    if (!arquivo) {
        cout << "Erro ao salvar arquivo!\n";
        return;
    }

    for (const auto& p : estoque) {
        arquivo << p.codigo << "|"
                << p.nome << "|"
                << p.categoria << "|"
                << p.preco << "|"
                << p.quantidade << "\n";
    }
}

// Carregar estoque
void carregarEstoque() {
    ifstream arquivo(ARQUIVO);
    string linha;

    while (getline(arquivo, linha)) {
        stringstream ss(linha);
        Produto p;
        string preco, quantidade;

        string codigo;
        if (!getline(ss, codigo, '|') ||
            !getline(ss, p.nome, '|') ||
            !getline(ss, p.categoria, '|') ||
            !getline(ss, preco, '|') ||
            !getline(ss, quantidade)) {
            continue;
        }

        try {
            p.codigo = stoi(codigo);
            p.preco = stod(preco);
            p.quantidade = stoi(quantidade);
            estoque.push_back(p);
        } catch (...) {
            continue;
        }
    }
}

// Cadastrar produto
void cadastrarProduto() {
    Produto p;

    cout << "\n===== CADASTRAR PRODUTO =====\n";

    p.codigo = lerInteiro("Codigo: ");

    if (buscarProduto(p.codigo) != -1) {
        cout << "Este codigo ja existe!\n";
        return;
    }

    p.nome = lerTexto("Nome: ");
    p.categoria = lerTexto("Categoria: ");
    p.preco = lerPreco("Preco: R$ ");
    p.quantidade = lerInteiro("Quantidade inicial: ");

    if (p.nome.empty() || p.categoria.empty()) {
        cout << "Nome e categoria nao podem ficar vazios!\n";
        return;
    }

    if (p.quantidade < 0) {
        cout << "Quantidade invalida!\n";
        return;
    }

    estoque.push_back(p);
    salvarEstoque();

    cout << "Produto cadastrado com sucesso!\n";
}

// Listar produtos
void listarProdutos() {
    cout << "\n========== ESTOQUE ==========\n";

    if (estoque.empty()) {
        cout << "Nenhum produto cadastrado.\n";
        return;
    }

    cout << left
         << setw(10) << "CODIGO"
         << setw(22) << "NOME"
         << setw(16) << "CATEGORIA"
         << setw(12) << "PRECO"
         << "QUANTIDADE\n";

    cout << string(75, '-') << "\n";

    for (const auto& p : estoque) {
        cout << left
             << setw(10) << p.codigo
             << setw(22) << p.nome
             << setw(16) << p.categoria
             << "R$ " << setw(9) << fixed
             << setprecision(2) << p.preco
             << p.quantidade << "\n";
    }
}

// Consultar produto
void consultarProduto() {
    cout << "\n===== CONSULTAR PRODUTO =====\n";

    int codigo = lerInteiro("Digite o codigo: ");
    int posicao = buscarProduto(codigo);

    if (posicao == -1) {
        cout << "Produto nao encontrado!\n";
        return;
    }

    Produto p = estoque[posicao];

    cout << "\nNome: " << p.nome;
    cout << "\nCategoria: " << p.categoria;
    cout << "\nPreco: R$ " << fixed << setprecision(2)
         << p.preco;
    cout << "\nQuantidade: " << p.quantidade << "\n";
}

// Entrada de mercadoria
void entradaProduto() {
    cout << "\n===== ENTRADA DE PRODUTOS =====\n";

    int codigo = lerInteiro("Codigo do produto: ");
    int posicao = buscarProduto(codigo);

    if (posicao == -1) {
        cout << "Produto nao encontrado!\n";
        return;
    }

    int quantidade = lerInteiro("Quantidade de entrada: ");

    if (quantidade <= 0) {
        cout << "Quantidade invalida!\n";
        return;
    }

    estoque[posicao].quantidade += quantidade;
    salvarEstoque();

    cout << "Entrada registrada!\n";
}

// Registrar venda
void registrarVenda() {
    cout << "\n===== REGISTRAR VENDA =====\n";

    int codigo = lerInteiro("Codigo do produto: ");
    int posicao = buscarProduto(codigo);

    if (posicao == -1) {
        cout << "Produto nao encontrado!\n";
        return;
    }

    int quantidade = lerInteiro("Quantidade vendida: ");

    if (quantidade <= 0) {
        cout << "Quantidade invalida!\n";
        return;
    }

    if (quantidade > estoque[posicao].quantidade) {
        cout << "Estoque insuficiente!\n";
        return;
    }

    double total = quantidade * estoque[posicao].preco;

    estoque[posicao].quantidade -= quantidade;
    salvarEstoque();

    cout << "\nVenda realizada!\n";
    cout << "Produto: " << estoque[posicao].nome << "\n";
    cout << "Quantidade: " << quantidade << "\n";
    cout << "Total: R$ " << fixed << setprecision(2)
         << total << "\n";
}

// Editar produto
void editarProduto() {
    cout << "\n===== EDITAR PRODUTO =====\n";

    int codigo = lerInteiro("Codigo do produto: ");
    int posicao = buscarProduto(codigo);

    if (posicao == -1) {
        cout << "Produto nao encontrado!\n";
        return;
    }

    Produto& p = estoque[posicao];
    cout << "Cadastro atual:\n";
    cout << "Nome: " << p.nome << "\n";
    cout << "Categoria: " << p.categoria << "\n";
    cout << "Preco: R$ " << fixed << setprecision(2) << p.preco << "\n";
    cout << "Quantidade: " << p.quantidade << "\n\n";

    cout << "Digite os novos dados:\n";
    string nome = lerTexto("Nome: ");
    string categoria = lerTexto("Categoria: ");
    double preco = lerPreco("Preco: R$ ");
    int quantidade = lerInteiro("Quantidade: ");

    if (nome.empty() || categoria.empty()) {
        cout << "Nome e categoria nao podem ficar vazios!\n";
        return;
    }

    if (quantidade < 0) {
        cout << "Quantidade invalida!\n";
        return;
    }

    p.nome = nome;
    p.categoria = categoria;
    p.preco = preco;
    p.quantidade = quantidade;
    salvarEstoque();

    cout << "Produto atualizado com sucesso!\n";
}

// Excluir produto
void excluirProduto() {
    cout << "\n===== EXCLUIR PRODUTO =====\n";

    int codigo = lerInteiro("Codigo: ");
    int posicao = buscarProduto(codigo);

    if (posicao == -1) {
        cout << "Produto nao encontrado!\n";
        return;
    }

    estoque.erase(estoque.begin() + posicao);
    salvarEstoque();

    cout << "Produto excluido!\n";
}

// Relatorio
void relatorioEstoque() {
    int totalUnidades = 0;
    double valorTotal = 0;

    cout << "\n===== RELATORIO DO ESTOQUE =====\n";

    for (const auto& p : estoque) {
        totalUnidades += p.quantidade;
        valorTotal += p.quantidade * p.preco;
    }

    cout << "Produtos cadastrados: " << estoque.size() << "\n";
    cout << "Total de unidades: " << totalUnidades << "\n";

    cout << "Valor do estoque: R$ "
         << fixed << setprecision(2)
         << valorTotal << "\n";

    cout << "\nProdutos com estoque baixo:\n";

    bool encontrou = false;

    for (const auto& p : estoque) {
        if (p.quantidade <= 5) {
            cout << p.nome << " - "
                 << p.quantidade << " unidades\n";
            encontrou = true;
        }
    }

    if (!encontrou) {
        cout << "Nenhum produto com estoque baixo.\n";
    }
}

// Menu principal
int main() {

    if (!autenticar()) {
        return 1;
    }

    carregarEstoque();

    int opcao;

    do {
        cout << "\n";
        cout << "====================================\n";
        cout << "       SISTEMA DE ESTOQUE\n";
        cout << "====================================\n";
        cout << "1 - Cadastrar produto\n";
        cout << "2 - Listar produtos\n";
        cout << "3 - Consultar produto\n";
        cout << "4 - Entrada de mercadoria\n";
        cout << "5 - Registrar venda\n";
        cout << "6 - Editar produto\n";
        cout << "7 - Excluir produto\n";
        cout << "8 - Relatorio de estoque\n";
        cout << "9 - Trocar senha\n";
        cout << "0 - Sair\n";
        cout << "====================================\n";

        opcao = lerInteiro("Escolha uma opcao: ");

        switch (opcao) {
            case 1:
                cadastrarProduto();
                break;

            case 2:
                listarProdutos();
                break;

            case 3:
                consultarProduto();
                break;

            case 4:
                entradaProduto();
                break;

            case 5:
                registrarVenda();
                break;

            case 6:
                editarProduto();
                break;

            case 7:
                excluirProduto();
                break;

            case 8:
                relatorioEstoque();
                break;

            case 9:
                trocarSenha();
                break;

            case 0:
                salvarEstoque();
                cout << "Sistema encerrado!\n";
                break;

            default:
                cout << "Opcao invalida!\n";
        }

    } while (opcao != 0);

    return 0;
}