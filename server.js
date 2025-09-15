const express = require('express');
const cors = require('cors');
const supabase = require('./supabaseClient');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'sua-chave-secreta-aqui';

// Middleware
app.use(cors());
app.use(express.json());

// Dados mockados (em produção usaria um banco de dados)
let users = [
  {
    id: '1',
    name: 'João Silva',
    email: 'joao@email.com',
    password: '$2b$10$example', // senha: 123456
    addresses: [
      {
        id: '1',
        street: 'Rua das Águas Claras, 123',
        neighborhood: 'Centro',
        city: 'Fortaleza',
        state: 'CE',
        zipCode: '60000-000',
      },
    ],
    creditCards: [
      {
        id: '1',
        brand: 'Visa',
        last4: '1234',
        expiry: '12/25',
      },
    ],
    selectedAddressId: '1',
    selectedCreditCardId: '1',
  },
];

const products = [
  {
    id: 1,
    name: 'Água Crystal 500ml',
    volume: '500ml',
    price: 2.5,
    image:
      'https://images.unsplash.com/photo-1550547660-d9450f859349?ixlib=rb-4.0.3&auto=format&fit=crop&w=400&q=80',
    description:
      'Água mineral natural cristalina, pureza e qualidade garantidas.',
    category: 'mineral',
    brand: 'Crystal',
    inStock: true,
  },
  {
    id: 2,
    name: 'Água São Lourenço 1.5L',
    volume: '1.5L',
    price: 3.9,
    image:
      'https://images.unsplash.com/photo-1548839140-29a749e1cf4d?ixlib=rb-4.0.3&auto=format&fit=crop&w=400&q=80',
    description:
      'Água mineral natural de São Lourenço, rica em minerais essenciais.',
    category: 'mineral',
    brand: 'São Lourenço',
    inStock: true,
  },
  {
    id: 3,
    name: 'Água Bonafont 1L',
    volume: '1L',
    price: 2.9,
    image:
      'https://images.unsplash.com/photo-1559827260-dc66d52bef19?ixlib=rb-4.0.3&auto=format&fit=crop&w=400&q=80',
    description: 'Água purificada Bonafont, ideal para hidratação diária.',
    category: 'purificada',
    brand: 'Bonafont',
    inStock: true,
  },
  {
    id: 4,
    name: 'Água Indaiá 510ml',
    volume: '510ml',
    price: 2.2,
    image:
      'https://images.unsplash.com/photo-1523362628745-0c100150b504?ixlib=rb-4.0.3&auto=format&fit=crop&w=400&q=80',
    description: 'Água mineral natural Indaiá, fonte de bem-estar e saúde.',
    category: 'mineral',
    brand: 'Indaiá',
    inStock: true,
  },
  {
    id: 5,
    name: 'Água Perrier 330ml',
    volume: '330ml',
    price: 6.5,
    image:
      'https://images.unsplash.com/photo-1571068316344-75bc76f77890?ixlib=rb-4.0.3&auto=format&fit=crop&w=400&q=80',
    description:
      'Água mineral com gás francesa Perrier, sofisticação em cada gole.',
    category: 'com_gas',
    brand: 'Perrier',
    inStock: true,
  },
];

let orders = [];

// Middleware de autenticação - DEPOIS
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Token de acesso requerido' });
  }

  const {
    data: { user },
    error,
  } = await supabase.auth.getUser(token);

  if (error || !user) {
    return res.status(403).json({ error: 'Token inválido ou expirado' });
  }

  req.user = user; // Adiciona o objeto user à requisição
  next();
};

// Rotas de Autenticação

// Rota de Registro - DEPOIS
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res
        .status(400)
        .json({ error: 'Nome, email e senha são obrigatórios' });
    }

    // 1. Cria o usuário no sistema de autenticação do Supabase
    const { data: authData, error: authError } = await supabase.auth.signUp({
      email: email,
      password: password,
    });

    if (authError) throw authError;
    if (!authData.user) throw new Error('Registro falhou, usuário não criado.');

    // 2. Insere os dados de perfil na nossa tabela 'users'
    const { error: profileError } = await supabase.from('users').insert({
      id: authData.user.id, // O ID vem do usuário autenticado
      name: name,
      email: email,
    });

    if (profileError) throw profileError;

    res
      .status(201)
      .json({ message: 'Usuário criado com sucesso', user: authData.user });
  } catch (error) {
    console.error(error);
    res.status(409).json({ error: error.message });
  }
});

// Rota de Login - DEPOIS
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email e senha são obrigatórios' });
    }

    const { data, error } = await supabase.auth.signInWithPassword({
      email: email,
      password: password,
    });

    if (error) throw error;

    // Pega os dados do perfil da nossa tabela 'users'
    const { data: userProfile, error: profileError } = await supabase
      .from('users')
      .select('*')
      .eq('id', data.user.id)
      .single();

    if (profileError) throw profileError;

    res.json({
      message: 'Login realizado com sucesso',
      token: data.session.access_token,
      user: userProfile,
    });
  } catch (error) {
    console.error(error);
    res.status(401).json({ error: 'Credenciais inválidas' });
  }
});

// Rota /verify - DEPOIS
app.get('/api/auth/verify', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { data: userProfile, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', userId)
      .single();

    if (error) throw error;
    if (!userProfile) {
      return res
        .status(404)
        .json({ error: 'Perfil do usuário não encontrado' });
    }

    res.json({ user: userProfile });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao verificar o usuário' });
  }
});

// Rotas de Produtos

// Lista todos os produtos - DEPOIS
app.get('/api/products', async (req, res) => {
  try {
    const { category, search } = req.query;

    let query = supabase.from('products').select('*');

    if (category) {
      query = query.eq('category', category);
    }

    if (search) {
      // Usando .ilike para busca case-insensitive
      query = query.ilike('name', `%${search}%`);
    }

    const { data, error } = await query;

    if (error) throw error;

    res.json({ products: data });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao buscar produtos' });
  }
});

// Detalhes de um produto - DEPOIS
app.get('/api/products/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { data, error } = await supabase
      .from('products')
      .select('*')
      .eq('id', id)
      .single(); // .single() retorna um objeto ao invés de um array

    if (error) throw error;

    if (!data) {
      return res.status(404).json({ error: 'Produto não encontrado' });
    }

    res.json({ product: data });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao buscar produto' });
  }
});
// Detalhes de um produto
app.get('/api/products/:id', (req, res) => {
  const product = products.find((p) => p.id === parseInt(req.params.id));

  if (!product) {
    return res.status(404).json({ error: 'Produto não encontrado' });
  }

  res.json({ product });
});

// Rotas de Endereços (autenticadas)

// Lista endereços do usuário - DEPOIS
app.get('/api/addresses', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { data, error } = await supabase
      .from('addresses')
      .select('*')
      .eq('user_id', userId);

    if (error) throw error;
    res.json({ addresses: data || [] });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao listar endereços' });
  }
});

// Adiciona novo endereço - DEPOIS
app.post('/api/addresses', authenticateToken, async (req, res) => {
  try {
    const { street, neighborhood, city, state, zip_code } = req.body;
    const userId = req.user.id;

    const { data, error } = await supabase
      .from('addresses')
      .insert({
        street,
        neighborhood,
        city,
        state,
        zip_code,
        user_id: userId,
      })
      .select()
      .single();

    if (error) throw error;

    res.status(201).json({
      message: 'Endereço adicionado com sucesso',
      address: data,
    });
  } catch (error) {
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Adiciona novo endereço
app.post('/api/addresses', authenticateToken, (req, res) => {
  try {
    const { street, neighborhood, city, state, zipCode } = req.body;

    if (!street || !neighborhood || !city || !state || !zipCode) {
      return res
        .status(400)
        .json({ error: 'Todos os campos são obrigatórios' });
    }

    const user = users.find((u) => u.id === req.user.id);
    const newAddress = {
      id: uuidv4(),
      street,
      neighborhood,
      city,
      state,
      zipCode,
    };

    user.addresses.push(newAddress);

    // Se for o primeiro endereço, seleciona automaticamente
    if (user.addresses.length === 1) {
      user.selectedAddressId = newAddress.id;
    }

    res.status(201).json({
      message: 'Endereço adicionado com sucesso',
      address: newAddress,
    });
  } catch (error) {
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Atualiza endereço
app.put('/api/addresses/:id', authenticateToken, (req, res) => {
  try {
    const { street, neighborhood, city, state, zipCode } = req.body;
    const addressId = req.params.id;

    const user = users.find((u) => u.id === req.user.id);
    const addressIndex = user.addresses.findIndex((a) => a.id === addressId);

    if (addressIndex === -1) {
      return res.status(404).json({ error: 'Endereço não encontrado' });
    }

    user.addresses[addressIndex] = {
      ...user.addresses[addressIndex],
      street,
      neighborhood,
      city,
      state,
      zipCode,
    };

    res.json({
      message: 'Endereço atualizado com sucesso',
      address: user.addresses[addressIndex],
    });
  } catch (error) {
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Rota para deletar endereço - DEPOIS
app.delete('/api/addresses/:id', authenticateToken, async (req, res) => {
  try {
    const addressId = req.params.id;
    const userId = req.user.id;

    const { error } = await supabase
      .from('addresses')
      .delete()
      .match({ id: addressId, user_id: userId }); // Garante que o usuário só delete seu próprio endereço

    if (error) throw error;

    res.json({ message: 'Endereço removido com sucesso' });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao remover endereço' });
  }
});

// Seleciona endereço
app.post('/api/addresses/:id/select', authenticateToken, (req, res) => {
  const user = users.find((u) => u.id === req.user.id);
  const address = user.addresses.find((a) => a.id === req.params.id);

  if (!address) {
    return res.status(404).json({ error: 'Endereço não encontrado' });
  }

  user.selectedAddressId = req.params.id;
  res.json({ message: 'Endereço selecionado com sucesso' });
});

// Rotas de Cartões de Crédito (autenticadas)

// Lista cartões do usuário
// Lista cartões do usuário - DEPOIS
app.get('/api/credit-cards', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { data, error } = await supabase
      .from('credit_cards') // Nome da sua tabela no Supabase
      .select('*')
      .eq('user_id', userId);

    if (error) throw error;

    res.json({ creditCards: data || [] });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao listar cartões de crédito.' });
  }
});

// Adiciona novo cartão - DEPOIS
app.post('/api/credit-cards', authenticateToken, async (req, res) => {
  try {
    const { brand, last4, expiry } = req.body;
    const userId = req.user.id;

    const { data, error } = await supabase
      .from('credit_cards')
      .insert({
        brand,
        last4,
        expiry,
        user_id: userId,
      })
      .select()
      .single();

    if (error) throw error;

    res.status(201).json({
      message: 'Cartão adicionado com sucesso',
      creditCard: data,
    });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao adicionar cartão.' });
  }
});

// Adiciona novo cartão
app.post('/api/credit-cards', authenticateToken, (req, res) => {
  try {
    const { brand, last4, expiry } = req.body;

    if (!brand || !last4 || !expiry) {
      return res
        .status(400)
        .json({ error: 'Todos os campos são obrigatórios' });
    }

    const user = users.find((u) => u.id === req.user.id);
    const newCard = {
      id: uuidv4(),
      brand,
      last4,
      expiry,
    };

    user.creditCards.push(newCard);

    // Se for o primeiro cartão, seleciona automaticamente
    if (user.creditCards.length === 1) {
      user.selectedCreditCardId = newCard.id;
    }

    res.status(201).json({
      message: 'Cartão adicionado com sucesso',
      creditCard: newCard,
    });
  } catch (error) {
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Remove cartão
app.delete('/api/credit-cards/:id', authenticateToken, (req, res) => {
  const user = users.find((u) => u.id === req.user.id);
  const cardIndex = user.creditCards.findIndex((c) => c.id === req.params.id);

  if (cardIndex === -1) {
    return res.status(404).json({ error: 'Cartão não encontrado' });
  }

  user.creditCards.splice(cardIndex, 1);

  // Se o cartão removido era o selecionado, limpa a seleção
  if (user.selectedCreditCardId === req.params.id) {
    user.selectedCreditCardId =
      user.creditCards.length > 0 ? user.creditCards[0].id : null;
  }

  res.json({ message: 'Cartão removido com sucesso' });
});

// Seleciona cartão
app.post('/api/credit-cards/:id/select', authenticateToken, (req, res) => {
  const user = users.find((u) => u.id === req.user.id);
  const card = user.creditCards.find((c) => c.id === req.params.id);

  if (!card) {
    return res.status(404).json({ error: 'Cartão não encontrado' });
  }

  user.selectedCreditCardId = req.params.id;
  res.json({ message: 'Cartão selecionado com sucesso' });
});

// Busca CEP (integração com ViaCEP)
app.get('/api/cep/:cep', async (req, res) => {
  try {
    const { cep } = req.params;
    const cleanCep = cep.replace(/\D/g, '');

    if (cleanCep.length !== 8) {
      return res.status(400).json({ error: 'CEP inválido' });
    }

    // Em uma implementação real, você faria uma requisição para a API ViaCEP
    // Aqui vou simular algumas respostas
    const mockCepData = {
      60000000: {
        cep: '60000-000',
        logradouro: 'Centro',
        bairro: 'Centro',
        localidade: 'Fortaleza',
        uf: 'CE',
      },
      '01310100': {
        cep: '01310-100',
        logradouro: 'Avenida Paulista',
        bairro: 'Bela Vista',
        localidade: 'São Paulo',
        uf: 'SP',
      },
    };

    const addressData = mockCepData[cleanCep];

    if (!addressData) {
      return res.status(404).json({ error: 'CEP não encontrado' });
    }

    res.json(addressData);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao buscar CEP' });
  }
});

// Rotas de Pedidos

// Lista pedidos do usuário
app.get('/api/orders', authenticateToken, (req, res) => {
  const userOrders = orders.filter((o) => o.userId === req.user.id);
  res.json({ orders: userOrders });
});

// Cria novo pedido
app.post('/api/orders', authenticateToken, (req, res) => {
  try {
    const { items, addressId, paymentMethod, paymentData } = req.body;

    if (!items || items.length === 0) {
      return res.status(400).json({ error: 'Itens são obrigatórios' });
    }

    if (!addressId) {
      return res
        .status(400)
        .json({ error: 'Endereço de entrega é obrigatório' });
    }

    const user = users.find((u) => u.id === req.user.id);
    const address = user.addresses.find((a) => a.id === addressId);

    if (!address) {
      return res.status(400).json({ error: 'Endereço inválido' });
    }

    // Calcula total
    const subtotal = items.reduce((sum, item) => {
      const product = products.find((p) => p.id === item.productId);
      return sum + product.price * item.quantity;
    }, 0);

    const shippingFee = subtotal > 100 ? 0 : 2.0;
    const total = subtotal + shippingFee;

    const newOrder = {
      id: uuidv4(),
      userId: req.user.id,
      items: items.map((item) => {
        const product = products.find((p) => p.id === item.productId);
        return {
          productId: item.productId,
          name: product.name,
          price: product.price,
          quantity: item.quantity,
          image: product.image,
        };
      }),
      address: address,
      paymentMethod,
      subtotal,
      shippingFee,
      total,
      status: 'confirmed',
      createdAt: new Date().toISOString(),
      estimatedDelivery: new Date(
        Date.now() + 2 * 60 * 60 * 1000
      ).toISOString(), // +2 horas
    };

    orders.push(newOrder);

    res.status(201).json({
      message: 'Pedido criado com sucesso',
      order: newOrder,
    });
  } catch (error) {
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Detalhes de um pedido
app.get('/api/orders/:id', authenticateToken, (req, res) => {
  const order = orders.find(
    (o) => o.id === req.params.id && o.userId === req.user.id
  );

  if (!order) {
    return res.status(404).json({ error: 'Pedido não encontrado' });
  }

  res.json({ order });
});

// Atualiza status do pedido (simulação)
app.put('/api/orders/:id/status', authenticateToken, (req, res) => {
  const { status } = req.body;
  const order = orders.find(
    (o) => o.id === req.params.id && o.userId === req.user.id
  );

  if (!order) {
    return res.status(404).json({ error: 'Pedido não encontrado' });
  }

  const validStatuses = [
    'confirmed',
    'preparing',
    'in_transit',
    'delivered',
    'cancelled',
  ];
  if (!validStatuses.includes(status)) {
    return res.status(400).json({ error: 'Status inválido' });
  }

  order.status = status;
  order.updatedAt = new Date().toISOString();

  res.json({
    message: 'Status do pedido atualizado',
    order,
  });
});

// Middleware de tratamento de erros
app.use((error, req, res, next) => {
  console.error(error);
  res.status(500).json({ error: 'Erro interno do servidor' });
});

// Rota 404
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Rota não encontrada' });
});

// Inicia o servidor
app.listen(PORT, () => {
  console.log(`🚀 Servidor rodando na porta ${PORT}`);
  console.log(`📱 API disponível em http://localhost:${PORT}/api`);
  console.log('\n📋 Rotas disponíveis:');
  console.log('🔐 Autenticação:');
  console.log('   POST /api/auth/register - Registrar usuário');
  console.log('   POST /api/auth/login - Login');
  console.log('   GET  /api/auth/verify - Verificar token');
  console.log('\n🛍️ Produtos:');
  console.log('   GET  /api/products - Listar produtos');
  console.log('   GET  /api/products/:id - Detalhes do produto');
  console.log('\n🏠 Endereços:');
  console.log('   GET    /api/addresses - Listar endereços');
  console.log('   POST   /api/addresses - Adicionar endereço');
  console.log('   PUT    /api/addresses/:id - Atualizar endereço');
  console.log('   DELETE /api/addresses/:id - Remover endereço');
  console.log('   POST   /api/addresses/:id/select - Selecionar endereço');
  console.log('\n💳 Cartões:');
  console.log('   GET    /api/credit-cards - Listar cartões');
  console.log('   POST   /api/credit-cards - Adicionar cartão');
  console.log('   DELETE /api/credit-cards/:id - Remover cartão');
  console.log('   POST   /api/credit-cards/:id/select - Selecionar cartão');
  console.log('\n🛒 Pedidos:');
  console.log('   GET  /api/orders - Listar pedidos');
  console.log('   POST /api/orders - Criar pedido');
  console.log('   GET  /api/orders/:id - Detalhes do pedido');
  console.log('   PUT  /api/orders/:id/status - Atualizar status');
  console.log('\n🔍 CEP:');
  console.log('   GET  /api/cep/:cep - Buscar endereço por CEP');
});

module.exports = app;
