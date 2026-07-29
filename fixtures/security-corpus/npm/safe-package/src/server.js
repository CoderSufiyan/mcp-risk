export function getDocument(documentId) {
  const documents = {
    'getting-started': 'Getting started',
    security: 'Security guidance',
  }
  return documents[documentId] ?? null
}
