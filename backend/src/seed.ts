// ============================================================================
// SENTINELA - Seed de Dados Iniciais
// Execute com: npm run db:seed
// ============================================================================

import { PrismaClient, PerfilUsuario, ProvedorApi } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Iniciando seed do banco de dados...\n');

  // 1. Criar organização padrão
  console.log('📁 Criando organização...');
  const organizacao = await prisma.organizacao.upsert({
    where: { cnpj: '00000000000000' },
    update: {},
    create: {
      nome: 'Organização Padrão',
      cnpj: '00000000000000',
      setor: 'Tecnologia',
      corPrimaria: '#0ea5e9',
    },
  });
  console.log(`   ✅ Organização criada: ${organizacao.nome}\n`);

  // 2. Criar usuário administrador
  console.log('👤 Criando usuário administrador...');
  const senhaHash = await bcrypt.hash('admin123', 12);
  
  const admin = await prisma.usuario.upsert({
    where: { email: 'admin@sentinela.app' },
    update: {},
    create: {
      nome: 'Administrador',
      email: 'admin@sentinela.app',
      senhaHash,
      ativo: true,
    },
  });
  
  await prisma.membro.upsert({
    where: {
      organizacaoId_usuarioId: {
        organizacaoId: organizacao.id,
        usuarioId: admin.id,
      },
    },
    update: {},
    create: {
      organizacaoId: organizacao.id,
      usuarioId: admin.id,
      perfil: PerfilUsuario.ADMINISTRADOR,
    },
  });
  console.log(`   ✅ Usuário criado: ${admin.email}`);
  console.log(`   📧 E-mail: admin@sentinela.app`);
  console.log(`   🔑 Senha: admin123\n`);

  // 3. Criar empresa de exemplo
  console.log('🏢 Criando empresa de exemplo...');
  const empresa = await prisma.empresa.upsert({
    where: { id: 'empresa-exemplo-001' },
    update: {},
    create: {
      id: 'empresa-exemplo-001',
      organizacaoId: organizacao.id,
      nome: 'Empresa Exemplo LTDA',
      nomeFantasia: 'Exemplo Corp',
      cnpj: '12345678000190',
      setor: 'Tecnologia',
      emailPrincipal: 'contato@exemplo.com.br',
      possuiConsentimento: true,
      dataConsentimento: new Date(),
      criadoPorId: admin.id,
      dominios: {
        create: [
          { dominio: 'exemplo.com.br', principal: true },
          { dominio: 'exemplodev.com.br', principal: false },
        ],
      },
    },
    include: { dominios: true },
  });
  console.log(`   ✅ Empresa criada: ${empresa.nome}`);
  console.log(`   🌐 Domínios: ${empresa.dominios.map(d => d.dominio).join(', ')}\n`);

  // 4. Criar monitoramento para a empresa
  console.log('📡 Ativando monitoramento...');
  await prisma.monitoramentoEmpresa.upsert({
    where: { empresaId: empresa.id },
    update: {},
    create: {
      empresaId: empresa.id,
      ativo: true,
      frequencia: 'diario',
    },
  });
  console.log('   ✅ Monitoramento ativado\n');

  // 5. Criar registro de auditoria inicial
  console.log('📋 Criando registro de auditoria...');
  await prisma.registroAuditoria.create({
    data: {
      organizacaoId: organizacao.id,
      usuarioId: admin.id,
      acao: 'SEED_INICIAL',
      tipoEntidade: 'SISTEMA',
      metadados: {
        versao: '1.0.0',
        data: new Date().toISOString(),
      },
    },
  });
  console.log('   ✅ Registro de auditoria criado\n');

  console.log('════════════════════════════════════════════════════════════');
  console.log('');
  console.log('   🎉 SEED CONCLUÍDO COM SUCESSO!');
  console.log('');
  console.log('   Acesse a plataforma com:');
  console.log('   📧 E-mail: admin@sentinela.app');
  console.log('   🔑 Senha: admin123');
  console.log('');
  console.log('   ⚠️  Lembre-se de alterar a senha após o primeiro acesso!');
  console.log('');
  console.log('════════════════════════════════════════════════════════════');
}

main()
  .catch((e) => {
    console.error('❌ Erro durante o seed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
