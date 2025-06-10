<script setup>
import { ref, watch, computed, nextTick } from 'vue'
import { useVueFlow, VueFlow } from '@vue-flow/core'

// these components are only shown as examples of how to use a custom node or edge
// you can find many examples of how to create these custom components in the examples page of the docs
import CallNode from '@/components/CallItem.vue'

const props = defineProps({
    nodes: {
        type: Array,
        required: true
    },
    edges: {
        type: Array,
        required: true
    }
})

// const Node = {
//     id: String,
//     type: String,
//     position: { x: Number, y: Number },
//     data:{
//       callName:String,
//     },
// }

// const Edge = {
//     id: String,
//     source: String,
//     target: String,
//     type: String,
// }

const m_nodes = ref(props.nodes)
const m_edges = ref(props.edges)

watch(() => props.nodes, (newNodes) => {
    m_nodes.value = newNodes;
    updateContainerSize();
}, { deep: true })

watch(() => props.edges, (newEdges) => {
    m_edges.value = newEdges
}, { deep: true })

const { onPaneReady } = useVueFlow()

onPaneReady((instance) => {
    instance.setViewport({ x: 10, y: 10, zoom: 1 });
});

const updateContainerSize = async () => {
    await nextTick();

    let maxWidth = 0;
    let maxHeight = 0;
    const lastMargin = 20;
    const fontWidth = 10;

    for (let i = 0; i < m_nodes.value.length; i++) {
        const item = m_nodes.value[i];
        const nodeWidth = item.data.callName.length * fontWidth + item.position.x;

        if (nodeWidth > maxWidth) {
            maxWidth = nodeWidth;
        }

        if (item.position.y + item.position.height + lastMargin > maxHeight) {
            maxHeight = item.position.y + item.position.height + lastMargin;
        }
    }

    containerWidth.value = maxWidth;
    containerHeight.value = maxHeight;
};

const containerWidth = ref(0)
const containerHeight = ref(0)
const containerStyle = computed(() => ({
    width: `${containerWidth.value}px`,
    height: `${containerHeight.value}px`,
    overflow: 'auto',
    display: 'flex',
    flexDirection: 'column'
}));
</script>

<template>
    <div :style="containerStyle">
        <VueFlow :nodes="m_nodes" :edges="m_edges" :style="{ background: 'white' }" :min-zoom="1.0" :max-zoom="1.0"
            :pan-on-drag="false" :pan-on-scroll="false" :zoom-on-scroll="false" :nodes-connectable="false">
            <template #node-callnode="callNodeProps">
                <CallNode :id="callNodeProps.id" :call-name="callNodeProps.data.callName" />
            </template>
        </VueFlow>
    </div>
</template>

<style>
/* import the necessary styles for Vue Flow to work */
@import '@vue-flow/core/dist/style.css';

/* import the default theme, this is optional but generally recommended */
@import '@vue-flow/core/dist/theme-default.css';
</style>