// Rota para geração de relatório PDF
// Adicionar após a rota GET /api/varreduras/:id

/*
app.get('/api/varreduras/:id/relatorio-pdf', autenticar, async (req: Request, res: Response) => {
  try {
    const orgId = req.usuario!.organizacaoId;
    const varreduraId = req.params.id;
    
    // Verificar se a varredura pertence à organização
    const varredura = await prisma.varredura.findFirst({
      where: { id: varreduraId, empresa: { organizacaoId: orgId } },
      include: { empresa: { select: { nome: true } } },
    });
    
    if (!varredura) {
      res.status(404).json({ erro: 'Varredura não encontrada' });
      return;
    }
    
    // Gerar PDF
    const pdfBuffer = await gerarRelatorioPDF(varreduraId);
    
    // Configurar headers para download
    const nomeArquivo = 'relatorio-' + varredura.empresa.nome.replace(/[^a-zA-Z0-9]/g, '_') + '-' + new Date().toISOString().split('T')[0] + '.pdf';
    
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename="' + nomeArquivo + '"');
    res.setHeader('Content-Length', pdfBuffer.length);
    
    res.send(pdfBuffer);
  } catch (erro: any) {
    console.error('Erro ao gerar PDF:', erro);
    res.status(500).json({ erro: erro.message });
  }
});
*/
