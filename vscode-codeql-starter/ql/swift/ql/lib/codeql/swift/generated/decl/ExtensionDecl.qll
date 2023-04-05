// generated by codegen/codegen.py
private import codeql.swift.generated.Synth
private import codeql.swift.generated.Raw
import codeql.swift.elements.decl.Decl
import codeql.swift.elements.decl.GenericContext
import codeql.swift.elements.decl.NominalTypeDecl
import codeql.swift.elements.decl.ProtocolDecl

module Generated {
  class ExtensionDecl extends Synth::TExtensionDecl, GenericContext, Decl {
    override string getAPrimaryQlClass() { result = "ExtensionDecl" }

    /**
     * Gets the extended type declaration of this extension declaration.
     *
     * This includes nodes from the "hidden" AST. It can be overridden in subclasses to change the
     * behavior of both the `Immediate` and non-`Immediate` versions.
     */
    NominalTypeDecl getImmediateExtendedTypeDecl() {
      result =
        Synth::convertNominalTypeDeclFromRaw(Synth::convertExtensionDeclToRaw(this)
              .(Raw::ExtensionDecl)
              .getExtendedTypeDecl())
    }

    /**
     * Gets the extended type declaration of this extension declaration.
     */
    final NominalTypeDecl getExtendedTypeDecl() {
      result = getImmediateExtendedTypeDecl().resolve()
    }

    /**
     * Gets the `index`th protocol of this extension declaration (0-based).
     *
     * This includes nodes from the "hidden" AST. It can be overridden in subclasses to change the
     * behavior of both the `Immediate` and non-`Immediate` versions.
     */
    ProtocolDecl getImmediateProtocol(int index) {
      result =
        Synth::convertProtocolDeclFromRaw(Synth::convertExtensionDeclToRaw(this)
              .(Raw::ExtensionDecl)
              .getProtocol(index))
    }

    /**
     * Gets the `index`th protocol of this extension declaration (0-based).
     */
    final ProtocolDecl getProtocol(int index) { result = getImmediateProtocol(index).resolve() }

    /**
     * Gets any of the protocols of this extension declaration.
     */
    final ProtocolDecl getAProtocol() { result = getProtocol(_) }

    /**
     * Gets the number of protocols of this extension declaration.
     */
    final int getNumberOfProtocols() { result = count(int i | exists(getProtocol(i))) }
  }
}