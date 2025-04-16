use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, spanned::Spanned, Data, DeriveInput, Error, Fields};

/// A derive macro that ensures a struct has no padding and is 8-byte aligned.
///
/// # Example
/// ```rust-ignore
/// #[derive(NoPadding)]
/// #[repr(C, align(8))]
/// struct MyStruct {
///     a: u32,
///     b: u64,
/// }
/// ```
#[proc_macro_derive(NoPadding)]
pub fn derive_no_padding(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    match impl_no_padding(&input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

fn impl_no_padding(input: &DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    // Check that we have repr(C) and repr(align(8))
    let repr_attrs: Vec<_> = input
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("repr"))
        .collect();

    if repr_attrs.is_empty() {
        return Err(Error::new(
            input.span(),
            "NoPadding requires #[repr(C, align(8))] to be specified",
        ));
    }

    let mut has_repr_c = false;
    let mut has_align_8 = false;

    for attr in &repr_attrs {
        if let Ok(meta) = attr.meta.require_list() {
            for nested in meta.parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            )? {
                match nested {
                    syn::Meta::Path(path) if path.is_ident("C") => {
                        has_repr_c = true;
                    },
                    syn::Meta::List(list) if list.path.is_ident("align") => {
                        if let Ok(lit) = list.parse_args::<syn::LitInt>() {
                            if lit.base10_parse::<usize>()? == 8 {
                                has_align_8 = true;
                            }
                        }
                    },
                    _ => {},
                }
            }
        }
    }

    if !has_repr_c || !has_align_8 {
        return Err(Error::new(
            repr_attrs[0].span(),
            "NoPadding requires #[repr(C, align(8))] to be specified",
        ));
    }

    // Get the struct fields
    let fields = match &input.data {
        Data::Struct(data) => &data.fields,
        _ => {
            return Err(Error::new(
                input.span(),
                "NoPadding can only be derived for structs",
            ))
        },
    };

    let struct_ident = &input.ident;
    let (_impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    // Generate size assertions
    let size_assertions = generate_size_assertions(fields, struct_ident)?;

    Ok(quote! {
        const _: () = {
            #size_assertions
        };

        #ty_generics #where_clause {}
    })
}

fn generate_size_assertions(
    fields: &Fields,
    struct_ident: &syn::Ident,
) -> syn::Result<proc_macro2::TokenStream> {
    let field_sizes = fields.iter().map(|field| {
        let ty = &field.ty;
        quote! {
            ::core::mem::size_of::<#ty>()
        }
    });

    Ok(quote! {
        const STRUCT_SIZE: usize = ::core::mem::size_of::<#struct_ident>();
        const FIELDS_SIZE: usize = 0 #( + #field_sizes)*;
        assert!(
            STRUCT_SIZE == FIELDS_SIZE,
            concat!(
                "Type has padding - size of struct (",
                ::core::stringify!(#struct_ident),
                ") does not match sum of field sizes"
            )
        );
    })
}
